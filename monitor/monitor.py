#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rift Guardians — monitor externo do servidor (item DI.MONITOR).

Roda no GitHub Actions do repositório público riftguardians-status (ver ../monitor.yml e o LEIAME).
Só usa a biblioteca padrão do Python e o GITHUB_TOKEN do próprio fluxo. Nenhum segredo é necessário.

O que confere:
  1. arquivo de estado assinado (estado.json) nos endereços públicos: assinatura, formato, idade,
     os dois lugares iguais, manutenção vencida;
  2. GET <api>/health: status, database, relay, pvp, simVersion;
  3. certificado HTTPS da API e do site: dias até vencer;
  4. o site abre.

Uma falha só vira incidente se persistir em TODAS as tentativas da mesma execução (padrão: 3, com 45 s
entre elas). Incidente = uma issue aberta no próprio repositório (o GitHub manda e-mail ao dono);
quando tudo volta, a issue é comentada e fechada. Nada é gravado no repositório a cada execução.

Uso:
  python monitor.py                 confere e cuida da issue (precisa de GITHUB_TOKEN e GITHUB_REPOSITORY)
  python monitor.py --dry-run       confere e só mostra o que faria
  python monitor.py --resumo ARQ    acrescenta o resumo da semana em ARQ (histórico; ver LEIAME)
  python monitor.py --self-test     testes sem rede
"""
import base64
import datetime as dt
import hashlib
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

AQUI = os.path.dirname(os.path.abspath(__file__))
ROTULO = "incidente-monitor"
MARCA = "<!-- rg-monitor:"
AGENTE = "rg-monitor (+https://github.com/%s)" % os.environ.get("GITHUB_REPOSITORY", "riftguardians-status")
PREFIXO_ESTADO = b"RG-ESTADO-1\n"
SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


# ----------------------------------------------------------------------------- utilidades

def agora():
    return dt.datetime.now(dt.timezone.utc)


def carregar_config(caminho=None):
    with open(caminho or os.path.join(AQUI, "config.json"), encoding="utf-8") as f:
        return json.load(f)


def baixar(url, limite=10, maximo=200_000):
    """GET simples. Devolve (status, corpo em bytes). Erro de rede vira exceção com texto curto."""
    pedido = urllib.request.Request(url, headers={"User-Agent": AGENTE, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(pedido, timeout=limite) as r:
            return r.status, r.read(maximo)
    except urllib.error.HTTPError as e:
        return e.code, e.read(maximo)


def dias_do_certificado(host, porta=443, limite=10):
    contexto = ssl.create_default_context()
    with socket.create_connection((host, porta), timeout=limite) as bruto:
        with contexto.wrap_socket(bruto, server_hostname=host) as s:
            fim = ssl.cert_time_to_seconds(s.getpeercert()["notAfter"])
    return (fim - time.time()) / 86400.0


def assinatura_confere(dados, assinatura, modulo_b64, expoente_b64):
    """RSA PKCS#1 v1.5 com SHA-256, como o jogo confere (potência modular + comparação do bloco inteiro)."""
    n = int.from_bytes(base64.b64decode(modulo_b64), "big")
    e = int.from_bytes(base64.b64decode(expoente_b64), "big")
    k = (n.bit_length() + 7) // 8
    if len(assinatura) != k:
        return False
    bloco = pow(int.from_bytes(assinatura, "big"), e, n).to_bytes(k, "big")
    resumo = SHA256_DIGESTINFO + hashlib.sha256(dados).digest()
    esperado = b"\x00\x01" + b"\xff" * (k - len(resumo) - 3) + b"\x00" + resumo
    return bloco == esperado


def ler_estado(texto, config):
    """Envelope assinado -> conteúdo (dict). Levanta ValueError com o motivo se não valer."""
    try:
        envelope = json.loads(texto)
        conteudo_bruto = base64.b64decode(envelope["payload"], validate=True)
        assinatura = base64.b64decode(envelope["sig"], validate=True)
    except Exception:
        raise ValueError("envelope ilegível")
    if envelope.get("format") != 1:
        raise ValueError("formato do envelope desconhecido")
    if not assinatura_confere(PREFIXO_ESTADO + conteudo_bruto, assinatura, config["estado_modulus"], config["estado_exponent"]):
        raise ValueError("assinatura não confere com a chave pública do jogo")
    conteudo = json.loads(conteudo_bruto.decode("utf-8"))
    if conteudo.get("format") != 1 or not str(conteudo.get("api", "")).startswith("https://"):
        raise ValueError("conteúdo inválido (format/api)")
    if not isinstance(conteudo.get("issuedAt"), int):
        raise ValueError("conteúdo sem issuedAt")
    return conteudo


def instante(texto):
    """'2026-10-12T08:00:00Z' -> datetime UTC (None se vazio ou ilegível)."""
    if not texto:
        return None
    try:
        return dt.datetime.fromisoformat(texto.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except ValueError:
        return None


# ----------------------------------------------------------------------------- coleta (rede)

def coletar(config):
    """Busca tudo uma vez. Devolve um dicionário de fatos brutos; avaliar() decide o que é falha."""
    fatos = {"quando": agora(), "estados": [], "health": None, "site": None, "certs": {}}
    for url in config["estado_urls"]:
        item = {"url": url}
        try:
            status, corpo = baixar(url + ("&" if "?" in url else "?") + "t=%d" % int(time.time()))
            if status != 200:
                raise ValueError("HTTP %d" % status)
            item["conteudo"] = ler_estado(corpo.decode("utf-8"), config)
        except Exception as erro:  # rede, HTTP, assinatura
            item["erro"] = str(erro)[:160]
        fatos["estados"].append(item)

    validos = [e["conteudo"] for e in fatos["estados"] if "conteudo" in e]
    estado = max(validos, key=lambda c: c["issuedAt"]) if validos else None
    api = (estado or {}).get("api") or config["api"]
    fatos["api"] = api.rstrip("/")

    try:
        status, corpo = baixar(fatos["api"] + "/health")
        try:
            dados = json.loads(corpo.decode("utf-8"))
        except Exception:
            dados = None
        fatos["health"] = {"http": status, "dados": dados if isinstance(dados, dict) else None}
    except Exception as erro:
        fatos["health"] = {"erro": str(erro)[:160]}

    try:
        status, corpo = baixar(config["site"])
        fatos["site"] = {"http": status, "tamanho": len(corpo)}
    except Exception as erro:
        fatos["site"] = {"erro": str(erro)[:160]}

    for host in sorted({urlparse(fatos["api"]).hostname, urlparse(config["site"]).hostname}):
        try:
            fatos["certs"][host] = {"dias": dias_do_certificado(host)}
        except Exception as erro:
            fatos["certs"][host] = {"erro": str(erro)[:160]}
    return fatos


# ----------------------------------------------------------------------------- avaliação (pura)

def avaliar(fatos, config):
    """Fatos -> lista de (id, ok, texto). Função pura: é o que o autoteste exercita."""
    r = []
    quando = fatos["quando"]

    # --- arquivo de estado
    validos = []
    for item in fatos["estados"]:
        nome = urlparse(item["url"]).hostname
        if "conteudo" in item:
            validos.append(item["conteudo"])
            r.append(("estado:" + nome, True, "arquivo de estado válido em %s" % nome))
        else:
            r.append(("estado:" + nome, False, "arquivo de estado em %s: %s" % (nome, item.get("erro", "?"))))
    estado = max(validos, key=lambda c: c["issuedAt"]) if validos else None
    manutencao = False
    if estado:
        emitido = dt.datetime.fromtimestamp(estado["issuedAt"], dt.timezone.utc)
        idade_h = (quando - emitido).total_seconds() / 3600.0
        if len(validos) > 1:
            diferenca = max(c["issuedAt"] for c in validos) - min(c["issuedAt"] for c in validos)
            # O Pages demora alguns minutos; só reclama se os dois lugares seguem diferentes depois de 1 h.
            iguais = diferenca == 0 or idade_h < 1
            r.append(("estado:iguais", iguais, "os dois lugares do arquivo de estado têm a mesma versão" if iguais
                      else "os dois lugares do arquivo de estado têm versões diferentes há mais de 1 h (publicar nos dois)"))
        velho = idade_h / 24.0 > config.get("estado_max_dias", 200)
        r.append(("estado:idade", not velho, "arquivo de estado assinado há %.0f dias" % (idade_h / 24.0)
                  + (" (acima do aviso de %d dias: reassinar e republicar)" % config.get("estado_max_dias", 200) if velho else "")))
        situacao = estado.get("state", "ok")
        if situacao == "maintenance":
            ate = instante(estado.get("until", ""))
            folga = dt.timedelta(minutes=config.get("manutencao_folga_min", 60))
            if ate is None:
                vencida = idade_h > config.get("manutencao_sem_prazo_h", 6)
                texto = "manutenção sem previsão há %.1f h" % idade_h
            else:
                vencida = quando > ate + folga
                texto = "manutenção com previsão %s" % ate.strftime("%d/%m %H:%M UTC")
            manutencao = not vencida
            r.append(("estado:manutencao", not vencida, texto + (" — VENCIDA: voltar o arquivo para ok ou atualizar a previsão" if vencida else " (dentro do prazo: falhas da API são esperadas)")))

    # --- API
    h = fatos["health"] or {}
    dados = h.get("dados")
    if manutencao:
        r.append(("api:manutencao", True, "API não conferida: manutenção anunciada e dentro do prazo"))
    elif "erro" in h:
        r.append(("api:responde", False, "API não responde em %s/health: %s" % (fatos["api"], h["erro"])))
    elif dados is None:
        r.append(("api:responde", False, "%s/health respondeu HTTP %s sem JSON" % (fatos["api"], h.get("http"))))
    else:
        r.append(("api:responde", True, "API responde (HTTP %s)" % h.get("http")))
        ok = h.get("http") == 200 and dados.get("status") == "ok"
        r.append(("api:status", ok, "status: %s" % dados.get("status")))
        ok = dados.get("database") == "ok"
        r.append(("api:database", ok, "banco: %s" % dados.get("database")))
        if config.get("relay_esperado", True):
            ok = dados.get("relay") == "ok"
            r.append(("api:relay", ok, "retransmissor de PvP: %s" % dados.get("relay")))
        pvp = dados.get("pvp")
        anunciado = bool(estado) and estado.get("state") in ("pvp_paused", "maintenance")
        if pvp == "paused":
            r.append(("api:pvp", anunciado, "PvP pausado no servidor" + ("" if anunciado else " mas o arquivo de estado não avisa os jogadores (state: pvp_paused)")))
        elif pvp is not None and config.get("relay_esperado", True):
            r.append(("api:pvp", pvp == "ok", "PvP online: %s" % pvp))
        sim = dados.get("simVersion")
        esperado = config.get("sim_version")
        ok = isinstance(sim, int) and sim > 0 and (esperado in (None, 0) or sim == esperado)
        r.append(("api:simVersion", ok, "simVersion: %s" % sim + ("" if ok else " (esperado %s)" % esperado)))
        if estado and estado.get("minVersion") and dados.get("minClientVersion") not in (None, "") \
                and estado["minVersion"] != dados["minClientVersion"]:
            r.append(("api:minVersion", False, "versão mínima diferente: servidor %s, arquivo de estado %s"
                      % (dados["minClientVersion"], estado["minVersion"])))
        # Campos de lotação (se o servidor já os publica): só informativos aqui.
        extras = {k: v for k, v in dados.items() if k not in
                  ("status", "database", "relay", "pvp", "simVersion", "minClientVersion", "serverDay", "time")}
        if extras:
            r.append(("api:lotacao", True, "outros campos do /health: " + json.dumps(extras, ensure_ascii=False, sort_keys=True)[:300]))

    # --- site
    s = fatos["site"] or {}
    if "erro" in s:
        r.append(("site", False, "site não abre: %s" % s["erro"]))
    else:
        ok = s.get("http") == 200 and s.get("tamanho", 0) > 200
        r.append(("site", ok, "site: HTTP %s, %s bytes" % (s.get("http"), s.get("tamanho"))))

    # --- certificados
    api_host = urlparse(fatos["api"]).hostname
    for host, c in sorted(fatos["certs"].items()):
        if "erro" in c:
            if host == api_host and manutencao:
                continue
            r.append(("cert:" + host, False, "certificado de %s: %s" % (host, c["erro"])))
        else:
            ok = c["dias"] >= config.get("cert_min_dias", 14)
            r.append(("cert:" + host, ok, "certificado de %s vence em %.0f dias" % (host, c["dias"])
                      + ("" if ok else " (a renovação automática deveria ter rodado: ver o Caddy / o Pages)")))
    return r


def confirmar(rodadas):
    """Várias avaliações seguidas -> falhas que persistiram em TODAS (id -> texto da última)."""
    if not rodadas:
        return {}
    ids = None
    for rodada in rodadas:
        falhou = {i for i, ok, _ in rodada if not ok}
        ids = falhou if ids is None else ids & falhou
    return {i: t for i, ok, t in rodadas[-1] if i in ids}


def decidir(falhas, issue):
    """(falhas confirmadas, issue aberta ou None) -> ação: 'nada' | 'abrir' | 'atualizar' | 'comentar' | 'fechar'."""
    assinatura = ",".join(sorted(falhas))
    if not falhas:
        return "fechar" if issue else "nada"
    if not issue:
        return "abrir"
    return "atualizar" if assinatura_da_issue(issue) == assinatura else "comentar"


def assinatura_da_issue(issue):
    corpo = issue.get("body") or ""
    inicio = corpo.find(MARCA)
    if inicio < 0:
        return ""
    return corpo[inicio + len(MARCA):corpo.find("-->", inicio)].strip()


def corpo_da_issue(falhas, resultado, desde):
    linhas = ["O monitor externo encontrou um problema que persistiu em todas as tentativas da execução.", "",
              "**Desde:** %s" % desde, "**Última conferência:** %s" % agora().strftime("%d/%m/%Y %H:%M UTC"), "",
              "### Com falha"]
    linhas += ["- ❌ `%s` — %s" % (i, t) for i, t in sorted(falhas.items())]
    linhas += ["", "### Tudo que foi conferido"]
    linhas += ["- %s `%s` — %s" % ("✅" if ok else "❌", i, t) for i, ok, t in resultado]
    linhas += ["", "O que fazer: `Server/OPERACAO.md` (seção \"O servidor caiu\") no repositório do jogo.",
               "Esta issue fecha sozinha quando tudo voltar.", "",
               "%s %s -->" % (MARCA, ",".join(sorted(falhas)))]
    return "\n".join(linhas)


# ----------------------------------------------------------------------------- GitHub e avisos

class GitHub:
    def __init__(self):
        self.repo = os.environ["GITHUB_REPOSITORY"]
        self.token = os.environ["GITHUB_TOKEN"]

    def chamar(self, metodo, caminho, corpo=None):
        dados = json.dumps(corpo).encode("utf-8") if corpo is not None else None
        pedido = urllib.request.Request("https://api.github.com/repos/%s%s" % (self.repo, caminho), data=dados, method=metodo, headers={
            "Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": AGENTE, "Content-Type": "application/json"})
        with urllib.request.urlopen(pedido, timeout=20) as r:
            texto = r.read().decode("utf-8")
            return json.loads(texto) if texto else None

    def issue_aberta(self):
        achadas = self.chamar("GET", "/issues?state=open&labels=%s&per_page=5" % ROTULO)
        achadas = [i for i in achadas if "pull_request" not in i]
        return achadas[-1] if achadas else None

    def issues_recentes(self, desde):
        return [i for i in self.chamar("GET", "/issues?state=all&labels=%s&per_page=100&since=%s" % (ROTULO, desde.strftime("%Y-%m-%dT%H:%M:%SZ")))
                if "pull_request" not in i]


def avisar_discord(texto):
    """Opcional: só se o dono criou o segredo DISCORD_WEBHOOK no repositório. O endereço nunca é mostrado."""
    url = os.environ.get("DISCORD_WEBHOOK", "").strip()
    if not url:
        return
    try:
        pedido = urllib.request.Request(url, data=json.dumps({"content": texto[:1800]}).encode("utf-8"),
                                        headers={"Content-Type": "application/json", "User-Agent": AGENTE}, method="POST")
        urllib.request.urlopen(pedido, timeout=10).read()
    except Exception:
        print("aviso: o webhook do Discord não respondeu (seguindo sem ele)")


def aplicar(acao, falhas, resultado, issue, gh):
    dono = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    resumo = "; ".join(t for _, t in sorted(falhas.items()))[:200]
    if acao == "abrir":
        desde = agora().strftime("%d/%m/%Y %H:%M UTC")
        corpo = {"title": "Servidor com problema: " + resumo[:120], "body": corpo_da_issue(falhas, resultado, desde), "labels": [ROTULO]}
        if dono:
            corpo["assignees"] = [dono]  # atribuir garante o e-mail mesmo sem "Watch" no repositório
        try:
            nova = gh.chamar("POST", "/issues", corpo)
        except urllib.error.HTTPError:
            corpo.pop("assignees", None)
            nova = gh.chamar("POST", "/issues", corpo)
        print("issue aberta: #%s" % nova["number"])
        avisar_discord("🔴 Rift Guardians — servidor com problema: %s\n%s" % (resumo, nova.get("html_url", "")))
    elif acao in ("atualizar", "comentar"):
        desde = dt.datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M UTC")
        gh.chamar("PATCH", "/issues/%s" % issue["number"], {"body": corpo_da_issue(falhas, resultado, desde)})
        if acao == "comentar":  # o conjunto de falhas mudou: comentário (gera e-mail); senão só edita o corpo (silencioso)
            gh.chamar("POST", "/issues/%s/comments" % issue["number"], {"body": "O problema mudou:\n" + "\n".join("- ❌ `%s` — %s" % p for p in sorted(falhas.items()))})
        print("issue #%s %s" % (issue["number"], "comentada" if acao == "comentar" else "atualizada"))
    elif acao == "fechar":
        aberta = dt.datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
        minutos = int((agora() - aberta).total_seconds() / 60)
        gh.chamar("POST", "/issues/%s/comments" % issue["number"], {"body": "✅ Tudo voltou ao normal em %s. Duração aproximada: %d min." % (agora().strftime("%d/%m/%Y %H:%M UTC"), minutos)})
        gh.chamar("PATCH", "/issues/%s" % issue["number"], {"state": "closed", "state_reason": "completed"})
        print("issue #%s fechada (%d min)" % (issue["number"], minutos))
        avisar_discord("🟢 Rift Guardians — tudo voltou ao normal (%d min)." % minutos)


# ----------------------------------------------------------------------------- comandos

def conferir(dry_run):
    config = carregar_config()
    tentativas = max(1, int(config.get("tentativas", 3)))
    rodadas = []
    for n in range(tentativas):
        resultado = avaliar(coletar(config), config)
        rodadas.append(resultado)
        if all(ok for _, ok, _ in resultado):
            break
        if n + 1 < tentativas:
            print("tentativa %d com falha; nova tentativa em %d s" % (n + 1, config.get("intervalo_s", 45)))
            time.sleep(config.get("intervalo_s", 45))
    resultado = rodadas[-1]
    falhas = confirmar(rodadas) if len(rodadas) == tentativas else {}
    linhas = ["%s %s — %s" % ("ok   " if ok else "FALHA", i, t) for i, ok, t in resultado]
    print("\n".join(linhas))
    print("falhas confirmadas em %d tentativa(s): %s" % (len(rodadas), ", ".join(sorted(falhas)) or "nenhuma"))
    sumario = os.environ.get("GITHUB_STEP_SUMMARY")
    if sumario:
        with open(sumario, "a", encoding="utf-8") as f:
            f.write("### Monitor — %s\n\n" % agora().strftime("%d/%m/%Y %H:%M UTC"))
            f.write("\n".join("- %s `%s` — %s" % ("✅" if ok else "❌", i, t) for i, ok, t in resultado) + "\n")
    if dry_run or not os.environ.get("GITHUB_TOKEN"):
        print("(sem GITHUB_TOKEN ou --dry-run: nenhuma issue foi tocada)")
        return 0
    gh = GitHub()
    issue = gh.issue_aberta()
    acao = decidir(falhas, issue)
    print("ação: " + acao)
    aplicar(acao, falhas, resultado, issue, gh)
    return 0


def resumo(arquivo):
    """Uma linha por semana no histórico (um commit por semana: pouco ruído e mantém o agendamento vivo)."""
    gh = GitHub()
    fim = agora()
    inicio = fim - dt.timedelta(days=7)
    incidentes, minutos, abertos = 0, 0, 0
    for i in gh.issues_recentes(inicio):
        criada = dt.datetime.fromisoformat(i["created_at"].replace("Z", "+00:00"))
        fechada = dt.datetime.fromisoformat(i["closed_at"].replace("Z", "+00:00")) if i.get("closed_at") else None
        if fechada and fechada < inicio:
            continue
        incidentes += 1 if criada >= inicio else 0
        abertos += 0 if fechada else 1
        minutos += int(((fechada or fim) - max(criada, inicio)).total_seconds() / 60)
    historico = []
    if os.path.exists(arquivo):
        with open(arquivo, encoding="utf-8") as f:
            historico = json.load(f)
    ano, semana, _ = fim.isocalendar()
    historico = [h for h in historico if h.get("semana") != "%d-S%02d" % (ano, semana)]
    historico.append({"semana": "%d-S%02d" % (ano, semana), "ate": fim.strftime("%Y-%m-%d"), "incidentes": incidentes,
                      "minutos_com_problema": minutos, "abertos": abertos,
                      "disponibilidade_pct": round(100.0 * (1 - minutos / (7 * 24 * 60.0)), 3)})
    with open(arquivo, "w", encoding="utf-8", newline="\n") as f:
        json.dump(historico[-104:], f, ensure_ascii=False, indent=1)
        f.write("\n")
    print("resumo da semana gravado em %s: %s" % (arquivo, historico[-1]))
    return 0


def autoteste():
    config = carregar_config()
    falhou = []

    def confere(nome, condicao):
        print("%s %s" % ("ok   " if condicao else "FALHA", nome))
        if not condicao:
            falhou.append(nome)

    # Assinatura: a constante de autoteste do jogo (Distribution.StateKeySelfTest) com a chave pública do config.
    sig = base64.b64decode(config["autoteste_assinatura"])
    texto = b"RG-AUTOTESTE-1\nrift guardians"
    confere("assinatura conhecida confere com a chave pública", assinatura_confere(texto, sig, config["estado_modulus"], config["estado_exponent"]))
    confere("texto adulterado é recusado", not assinatura_confere(texto + b"x", sig, config["estado_modulus"], config["estado_exponent"]))
    try:
        ler_estado(json.dumps({"format": 1, "payload": base64.b64encode(b'{"format":1}').decode(), "sig": base64.b64encode(sig).decode()}), config)
        confere("arquivo de estado com assinatura de outra coisa é recusado", False)
    except ValueError:
        confere("arquivo de estado com assinatura de outra coisa é recusado", True)

    t0 = dt.datetime(2026, 10, 12, 12, 0, tzinfo=dt.timezone.utc)
    emitido = int((t0 - dt.timedelta(days=3)).timestamp())

    def fatos(estado=None, health=None, site=None, dias=60, estados=None):
        base = {"format": 1, "api": "https://api.exemplo.test", "issuedAt": emitido, "state": "ok", "minVersion": "0.9.0"}
        base.update(estado or {})
        saude = {"http": 200, "dados": {"status": "ok", "database": "ok", "relay": "ok", "pvp": "ok", "simVersion": 16, "minClientVersion": "0.9.0"}}
        if health is not None:
            saude = health
        return {"quando": t0, "api": "https://api.exemplo.test",
                "estados": estados if estados is not None else [{"url": "https://a.test/estado.json", "conteudo": base}, {"url": "https://b.test/estado.json", "conteudo": dict(base)}],
                "health": saude, "site": site or {"http": 200, "tamanho": 5000},
                "certs": {"api.exemplo.test": {"dias": dias}, "exemplo.test": {"dias": 80}}}

    def falhas(f):
        return sorted(i for i, ok, _ in avaliar(f, config) if not ok)

    confere("tudo certo não gera falha", falhas(fatos()) == [])
    confere("API fora do ar", falhas(fatos(health={"erro": "timed out"})) == ["api:responde"])
    confere("banco fora (503 degraded)", falhas(fatos(health={"http": 503, "dados": {"status": "degraded", "database": "fora do ar", "relay": "ok", "pvp": "ok", "simVersion": 16}})) == ["api:database", "api:status"])
    confere("retransmissor desligado", "api:relay" in falhas(fatos(health={"http": 200, "dados": {"status": "ok", "database": "ok", "relay": "desligado", "pvp": "desligado", "simVersion": 16}})))
    pausado = {"http": 200, "dados": {"status": "ok", "database": "ok", "relay": "ok", "pvp": "paused", "simVersion": 16}}
    confere("PvP pausado sem aviso no arquivo de estado é falha", falhas(fatos(health=pausado)) == ["api:pvp"])
    confere("PvP pausado com aviso não é falha", falhas(fatos(estado={"state": "pvp_paused"}, health=pausado)) == [])
    confere("certificado perto de vencer", falhas(fatos(dias=5)) == ["cert:api.exemplo.test"])
    confere("site fora", falhas(fatos(site={"http": 404, "tamanho": 90})) == ["site"])
    confere("versão mínima diferente", falhas(fatos(estado={"minVersion": "1.0.0"})) == ["api:minVersion"])
    confere("manutenção no prazo cala as falhas da API", falhas(fatos(estado={"state": "maintenance", "until": "2026-10-12T13:00:00Z"}, health={"erro": "recusada"})) == [])
    confere("manutenção vencida é falha", falhas(fatos(estado={"state": "maintenance", "until": "2026-10-12T08:00:00Z"})) == ["estado:manutencao"])
    confere("um lugar do arquivo de estado fora", falhas(fatos(estados=[{"url": "https://a.test/estado.json", "erro": "HTTP 404"}, {"url": "https://b.test/estado.json", "conteudo": {"format": 1, "api": "https://api.exemplo.test", "issuedAt": emitido}}])) == ["estado:a.test"])
    confere("lugares com versões diferentes há mais de 1 h", "estado:iguais" in falhas(fatos(estados=[
        {"url": "https://a.test/estado.json", "conteudo": {"format": 1, "api": "https://api.exemplo.test", "issuedAt": emitido}},
        {"url": "https://b.test/estado.json", "conteudo": {"format": 1, "api": "https://api.exemplo.test", "issuedAt": emitido - 9000}}])))
    confere("campos novos do /health não quebram", falhas(fatos(health={"http": 200, "dados": {"status": "ok", "database": "ok", "relay": "ok", "pvp": "ok", "simVersion": 16, "online": 12, "pvpRooms": 3, "maxOnline": 150}})) == [])

    a = [("x", False, "x"), ("y", False, "y"), ("z", True, "z")]
    b = [("x", False, "x2"), ("y", True, "y"), ("z", True, "z")]
    confere("soluço (falha em 1 de 2 tentativas) não confirma", confirmar([a, b]) == {"x": "x2"})
    confere("sem falha e sem issue: nada", decidir({}, None) == "nada")
    confere("falha sem issue: abrir", decidir({"x": "t"}, None) == "abrir")
    issue = {"body": corpo_da_issue({"x": "t"}, a, "agora")}
    confere("mesma falha com issue: só atualiza (sem e-mail)", decidir({"x": "t"}, issue) == "atualizar")
    confere("falha diferente com issue: comenta", decidir({"x": "t", "y": "t"}, issue) == "comentar")
    confere("voltou com issue: fechar", decidir({}, issue) == "fechar")
    print("AUTOTESTE: %s" % ("%d FALHA(S)" % len(falhou) if falhou else "tudo certo"))
    return 1 if falhou else 0


if __name__ == "__main__":
    for fluxo in (sys.stdout, sys.stderr):
        try:
            fluxo.reconfigure(encoding="utf-8")
        except Exception:
            pass
    args = sys.argv[1:]
    if "--self-test" in args:
        sys.exit(autoteste())
    if "--resumo" in args:
        sys.exit(resumo(args[args.index("--resumo") + 1]))
    sys.exit(conferir("--dry-run" in args))
