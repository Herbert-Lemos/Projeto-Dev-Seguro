import sqlite3
import hashlib
import hmac
import os
import getpass
from datetime import datetime

#Login inicial:  usuario = admin   senha = Admin@123

NOME_BANCO = "estoque.db"
MAX_TENTATIVAS = 3

PERMISSOES = {
    "admin": [
        "listar", "buscar", "cadastrar_produto", "alterar_quantidade",
        "excluir_produto", "cadastrar_usuario", "ver_logs",
    ],
    "comum": ["listar", "buscar"],
}


def conectar():
    return sqlite3.connect(NOME_BANCO)


def criar_tabelas():
    con = conectar()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL,
            senha_hash TEXT NOT NULL,
            perfil TEXT NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            quantidade INTEGER NOT NULL,
            preco REAL NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data_hora TEXT NOT NULL,
            usuario TEXT NOT NULL,
            acao TEXT NOT NULL
        )
    """)
    con.commit()
    con.close()


def registrar_log(usuario, acao):
    data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    con = conectar()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO logs (data_hora, usuario, acao) VALUES (?, ?, ?)",
        (data_hora, usuario, acao),
    )
    con.commit()
    con.close()


def gerar_hash(senha, salt_hex):
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256", senha.encode("utf-8"), bytes.fromhex(salt_hex), 100000
    )
    return hash_bytes.hex()


def criar_usuario_no_banco(username, senha, perfil):
    salt = os.urandom(16).hex()
    senha_hash = gerar_hash(senha, salt)
    con = conectar()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO usuarios (username, salt, senha_hash, perfil) VALUES (?, ?, ?, ?)",
        (username, salt, senha_hash, perfil),
    )
    con.commit()
    con.close()


def criar_admin_inicial():
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM usuarios")
    total = cur.fetchone()[0]
    con.close()
    if total == 0:
        criar_usuario_no_banco("admin", "Admin@123", "admin")
        registrar_log("sistema", "Administrador inicial criado")


def pedir_senha(mensagem):
    try:
        return getpass.getpass(mensagem)
    except Exception:
        return input(mensagem)


def validar_username(username):
    if len(username) < 3 or len(username) > 20:
        print("Erro: o usuario deve ter entre 3 e 20 caracteres.")
        return False
    if not username.replace("_", "").isalnum():
        print("Erro: use apenas letras, numeros e underline (_).")
        return False
    return True


def validar_senha(senha):
    if len(senha) < 6:
        print("Erro: a senha deve ter pelo menos 6 caracteres.")
        return False
    tem_letra = any(c.isalpha() for c in senha)
    tem_numero = any(c.isdigit() for c in senha)
    if not (tem_letra and tem_numero):
        print("Erro: a senha deve ter pelo menos uma letra e um numero.")
        return False
    return True


def ler_nome_produto():
    nome = input("Nome do produto: ").strip()
    if len(nome) < 2 or len(nome) > 50:
        print("Erro: o nome deve ter entre 2 e 50 caracteres.")
        return None
    return nome


def ler_inteiro_nao_negativo(mensagem):
    texto = input(mensagem).strip()
    try:
        valor = int(texto)
    except ValueError:
        print("Erro: digite um numero inteiro (ex.: 10).")
        return None
    if valor < 0:
        print("Erro: o valor nao pode ser negativo.")
        return None
    return valor


def ler_preco():
    texto = input("Preco (ex.: 12.50): ").strip().replace(",", ".")
    try:
        valor = float(texto)
    except ValueError:
        print("Erro: digite um preco valido (ex.: 12.50).")
        return None
    if valor <= 0:
        print("Erro: o preco deve ser maior que zero.")
        return None
    return valor


def fazer_login():
    for tentativa in range(1, MAX_TENTATIVAS + 1):
        username = input("Usuario: ").strip()
        senha = pedir_senha("Senha: ")

        con = conectar()
        cur = con.cursor()
        cur.execute(
            "SELECT salt, senha_hash, perfil FROM usuarios WHERE username = ?",
            (username,),
        )
        linha = cur.fetchone()
        con.close()

        if linha is not None:
            salt, hash_salvo, perfil = linha
            hash_digitado = gerar_hash(senha, salt)
            if hmac.compare_digest(hash_salvo, hash_digitado):
                registrar_log(username, "Login realizado com sucesso")
                print(f"\nBem-vindo, {username}! (perfil: {perfil})")
                return {"nome": username, "perfil": perfil}

        print(f"Usuario ou senha invalidos. Tentativa {tentativa} de {MAX_TENTATIVAS}.")
        registrar_log(username if username else "(vazio)", "Tentativa de login invalida")

    print("Numero maximo de tentativas atingido. Encerrando o sistema.")
    registrar_log("sistema", "Login bloqueado apos 3 tentativas invalidas")
    return None


def tem_permissao(usuario, acao):
    if acao in PERMISSOES.get(usuario["perfil"], []):
        return True
    print("ACESSO NEGADO: seu perfil nao tem permissao para esta operacao.")
    registrar_log(usuario["nome"], f"ACESSO NEGADO: tentou '{acao}'")
    return False


def listar_produtos(usuario):
    if not tem_permissao(usuario, "listar"):
        return
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT id, nome, quantidade, preco FROM produtos ORDER BY id")
    produtos = cur.fetchall()
    con.close()

    if not produtos:
        print("Nenhum produto cadastrado.")
    else:
        print(f"\n{'ID':<5}{'NOME':<30}{'QTD':<8}{'PRECO':>10}")
        print("-" * 53)
        for p in produtos:
            print(f"{p[0]:<5}{p[1]:<30}{p[2]:<8}{p[3]:>10.2f}")
    registrar_log(usuario["nome"], "Listou os produtos")


def buscar_produto(usuario):
    if not tem_permissao(usuario, "buscar"):
        return
    termo = input("Digite parte do nome: ").strip()
    if termo == "":
        print("Erro: digite algo para buscar.")
        return
    con = conectar()
    cur = con.cursor()
    cur.execute(
        "SELECT id, nome, quantidade, preco FROM produtos WHERE nome LIKE ?",
        ("%" + termo + "%",),
    )
    resultados = cur.fetchall()
    con.close()

    if not resultados:
        print("Nenhum produto encontrado.")
    else:
        for p in resultados:
            print(f"ID {p[0]} | {p[1]} | Qtd: {p[2]} | R$ {p[3]:.2f}")
    registrar_log(usuario["nome"], f"Buscou produto: '{termo}'")


def cadastrar_produto(usuario):
    if not tem_permissao(usuario, "cadastrar_produto"):
        return
    nome = ler_nome_produto()
    if nome is None:
        return
    quantidade = ler_inteiro_nao_negativo("Quantidade: ")
    if quantidade is None:
        return
    preco = ler_preco()
    if preco is None:
        return

    con = conectar()
    cur = con.cursor()
    cur.execute(
        "INSERT INTO produtos (nome, quantidade, preco) VALUES (?, ?, ?)",
        (nome, quantidade, preco),
    )
    con.commit()
    con.close()
    print("Produto cadastrado com sucesso!")
    registrar_log(usuario["nome"], f"Cadastrou produto: {nome}")


def alterar_quantidade(usuario):
    if not tem_permissao(usuario, "alterar_quantidade"):
        return
    id_produto = ler_inteiro_nao_negativo("ID do produto: ")
    if id_produto is None:
        return
    nova_qtd = ler_inteiro_nao_negativo("Nova quantidade: ")
    if nova_qtd is None:
        return

    con = conectar()
    cur = con.cursor()
    cur.execute("UPDATE produtos SET quantidade = ? WHERE id = ?", (nova_qtd, id_produto))
    alterou = cur.rowcount
    con.commit()
    con.close()

    if alterou == 0:
        print("Erro: produto nao encontrado.")
    else:
        print("Quantidade atualizada!")
        registrar_log(
            usuario["nome"],
            f"Alterou quantidade do produto ID {id_produto} para {nova_qtd}",
        )


def excluir_produto(usuario):
    if not tem_permissao(usuario, "excluir_produto"):
        return
    id_produto = ler_inteiro_nao_negativo("ID do produto a excluir: ")
    if id_produto is None:
        return
    confirmar = input("Tem certeza? (s/n): ").strip().lower()
    if confirmar != "s":
        print("Exclusao cancelada.")
        return

    con = conectar()
    cur = con.cursor()
    cur.execute("DELETE FROM produtos WHERE id = ?", (id_produto,))
    apagou = cur.rowcount
    con.commit()
    con.close()

    if apagou == 0:
        print("Erro: produto nao encontrado.")
    else:
        print("Produto excluido.")
        registrar_log(usuario["nome"], f"Excluiu produto ID {id_produto}")


def cadastrar_usuario(usuario):
    if not tem_permissao(usuario, "cadastrar_usuario"):
        return
    username = input("Novo usuario: ").strip()
    if not validar_username(username):
        return
    senha = pedir_senha("Senha do novo usuario: ")
    if not validar_senha(senha):
        return
    perfil = input("Perfil (admin/comum): ").strip().lower()
    if perfil not in PERMISSOES:
        print("Erro: perfil invalido. Use 'admin' ou 'comum'.")
        return

    try:
        criar_usuario_no_banco(username, senha, perfil)
    except sqlite3.IntegrityError:
        print("Erro: este nome de usuario ja existe.")
        return
    print("Usuario criado com sucesso!")
    registrar_log(usuario["nome"], f"Criou usuario '{username}' com perfil '{perfil}'")


def ver_logs(usuario):
    if not tem_permissao(usuario, "ver_logs"):
        return
    con = conectar()
    cur = con.cursor()
    cur.execute("SELECT data_hora, usuario, acao FROM logs ORDER BY id DESC LIMIT 30")
    registros = cur.fetchall()
    con.close()

    print("\n--- ULTIMOS 30 REGISTROS ---")
    for data_hora, user, acao in registros:
        print(f"[{data_hora}] {user}: {acao}")


def mostrar_menu(usuario):
    print("\n========== ESTOQUE ==========")
    print("1 - Listar produtos")
    print("2 - Buscar produto")
    print("3 - Cadastrar produto      (admin)")
    print("4 - Alterar quantidade     (admin)")
    print("5 - Excluir produto        (admin)")
    print("6 - Cadastrar usuario      (admin)")
    print("7 - Ver logs               (admin)")
    print("0 - Sair")
    print(f"Logado como: {usuario['nome']} ({usuario['perfil']})")


def main():
    criar_tabelas()
    criar_admin_inicial()

    print("=== SISTEMA DE CONTROLE DE ESTOQUE ===")
    usuario = fazer_login()
    if usuario is None:
        return

    while True:
        mostrar_menu(usuario)
        opcao = input("Escolha: ").strip()

        if opcao == "1":
            listar_produtos(usuario)
        elif opcao == "2":
            buscar_produto(usuario)
        elif opcao == "3":
            cadastrar_produto(usuario)
        elif opcao == "4":
            alterar_quantidade(usuario)
        elif opcao == "5":
            excluir_produto(usuario)
        elif opcao == "6":
            cadastrar_usuario(usuario)
        elif opcao == "7":
            ver_logs(usuario)
        elif opcao == "0":
            registrar_log(usuario["nome"], "Logout")
            print("Ate logo!")
            break
        else:
            print("Opcao invalida. Escolha um numero do menu.")


if __name__ == "__main__":
    main()