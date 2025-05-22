# Projeto PIM - 1º Semestre de ADS - UNIP
# Desenvolvido por: Felipe Felix
# Sistema de cadastro e análise de usuários com segurança e estatísticas

import json
import os
import secrets
import time
import base64
import hashlib
import binascii
import matplotlib.pyplot as plt
import getpass
from statistics import mean, median, mode
from cryptography.fernet import Fernet, InvalidToken
from collections import Counter
from collections import defaultdict

# Diretório base fixo na pasta do script
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Arquivos
DATA_FILE = os.path.join(BASE_DIR, 'dados.json')
KEY_FILE = os.path.join(BASE_DIR, 'chave.key')
BACKUP_FILE = os.path.join(BASE_DIR, 'backup.json')
USERS_FILE = os.path.join(BASE_DIR, 'usuarios.json')
def gerar_chave():
    chave = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as keyfile:
        keyfile.write(chave)
    return chave

def carregar_chave():
    if not os.path.exists(KEY_FILE):
        return gerar_chave()
    with open(KEY_FILE, 'rb') as keyfile:
        return keyfile.read()

def criptografar(dado):
    chave = carregar_chave()
    fernet = Fernet(chave)
    return fernet.encrypt(dado.encode()).decode('utf-8')

def corrigir_padding(base64_string):
    return base64_string + '=' * (-len(base64_string) % 4)

def descriptografar(dado):
    chave = carregar_chave()
    fernet = Fernet(chave)
    try:
        dado = corrigir_padding(dado)
        return fernet.decrypt(dado.encode()).decode('utf-8')
    except (binascii.Error, InvalidToken):
        return "Dado protegido pela LGPD"
def carregar_dados():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    else:
        with open(DATA_FILE, 'w') as file:
            json.dump([], file)
        return []

def carregar_desempenho():
    if os.path.exists(DESEMPENHO_FILE):
        with open(DESEMPENHO_FILE, 'r') as file:
            return json.load(file)
    return []

def salvar_dados(dado):
    dados = carregar_dados()
    dados.append(dado)
    with open(DATA_FILE, 'w') as file:
        json.dump(dados, file)

def criar_backup():
    dados = carregar_dados()
    with open(BACKUP_FILE, 'w') as file:
        json.dump(dados, file)
    print("Backup criado com sucesso.")

def analise_estatistica(valores):
    return mean(valores), mode(valores), median(valores)

def exibir_grafico(dados, titulo):
    plt.figure(figsize=(8,6))
    plt.bar(dados.keys(), dados.values(), color='skyblue')
    plt.title(titulo)
    plt.xticks(rotation=45, ha="right")
    plt.ylim(0, max(dados.values()) + 5)
    plt.tight_layout()
    plt.show()

def grafico_desempenho_por_curso():
    desempenho = carregar_desempenho()
    acertos_por_curso = defaultdict(list)

    for d in desempenho:
        acertos_por_curso[d['curso']].append(d['acertos'])

   
    media_acertos = {
        curso: (sum(acertos) / len(acertos)) / 3 * 10
        for curso, acertos in acertos_por_curso.items()
    }

    plt.bar(media_acertos.keys(), media_acertos.values(), color='lightgreen')
    plt.title("Média de Desempenho por Curso (0 a 10)")
    plt.xlabel("Curso")
    plt.ylabel("Nota Média")
    plt.ylim(0, 10)
    plt.show()

def grafico_alunos_por_curso():
    desempenho = carregar_desempenho()
    cursos = [d['curso'] for d in desempenho]
    contagem = Counter(cursos)
    plt.bar(contagem.keys(), contagem.values(), color='lightblue')
    plt.title("Quantidade de Alunos por Curso")
    plt.xlabel("Curso")
    plt.ylabel("Número de Alunos")
    plt.show()

def exibir_grafico_tempo(dados, titulo):
    max_val = max(dados.values()) if dados else 0
    if max_val < 1:  # menos de 1 hora
        dados_ajustados = {f"Usuário {i+1}": v * 60 for i, (k, v) in enumerate(dados.items())}
        unidade = "minutos"
    else:
        dados_ajustados = {f"Usuário {i+1}": v for i, (k, v) in enumerate(dados.items())}
        unidade = "horas"

    plt.figure(figsize=(8,6))
    plt.bar(dados_ajustados.keys(), dados_ajustados.values(), color='skyblue')
    plt.title(f"{titulo} ({unidade})")
    plt.xticks(rotation=45, ha="right")
    plt.ylim(0, max(dados_ajustados.values()) * 1.1)  # margem para visualização
    plt.tight_layout()
    plt.show()

def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

def carregar_usuarios():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    else:
        with open(USERS_FILE, 'w') as file:
            json.dump({}, file)
        return {}

def salvar_usuario(usuario, senha):
    usuarios = carregar_usuarios()
    usuarios[usuario] = hash_senha(senha)
    with open(USERS_FILE, 'w') as file:
        json.dump(usuarios, file)
def registrar_usuario_com_dados(usuario, senha, nome, idade, tipo='aluno'):
    salvar_usuario(usuario, senha)
    dados = carregar_dados()
    for d in dados:
        if descriptografar(d['nome']) == usuario:
            return  # já existe
    dados.append({
        'nome': criptografar(usuario),
        'idade': idade,
        'acessos': 0,
        'tempo_uso': 0,
        'senha': criptografar(senha),
        'tipo': tipo
    })
    with open(DATA_FILE, 'w') as file:
        json.dump(dados, file)

def verificar_login(usuario, senha):
    usuarios = carregar_usuarios()
    return usuario in usuarios and usuarios[usuario] == hash_senha(senha)

def obter_tipo_usuario(usuario):
    dados = carregar_dados()
    for d in dados:
        if descriptografar(d['nome']) == usuario:
            return d.get('tipo', 'aluno')
    return 'aluno'

def atualizar_tempo_uso(usuario, tempo_uso):
    dados = carregar_dados()
    for d in dados:
        if descriptografar(d['nome']) == usuario:
            d['tempo_uso'] += tempo_uso
            break
    with open(DATA_FILE, 'w') as file:
        json.dump(dados, file)

def incrementar_acessos(usuario):
    dados = carregar_dados()
    for d in dados:
        if descriptografar(d['nome']) == usuario:
            d['acessos'] += 1
            break
    with open(DATA_FILE, 'w') as file:
        json.dump(dados, file)

def excluir_usuario(usuario):
    usuarios = carregar_usuarios()
    dados = carregar_dados()

    if usuario not in usuarios:
        print(f"Usuário '{usuario}' não encontrado em usuarios.json.")
        return

    del usuarios[usuario]
    with open(USERS_FILE, 'w') as file:
        json.dump(usuarios, file)
    print(f"Usuário '{usuario}' removido de usuarios.json.")

    dados = [d for d in dados if descriptografar(d['nome']) != usuario]
    with open(DATA_FILE, 'w') as file:
        json.dump(dados, file)
    print(f"Usuário '{usuario}' removido de dados.json.")

from datetime import datetime

DESEMPENHO_FILE = os.path.join(BASE_DIR, 'desempenho.json')

def salvar_desempenho(usuario, curso, acertos):
    desempenho = []
    if os.path.exists(DESEMPENHO_FILE):
        with open(DESEMPENHO_FILE, 'r') as file:
            desempenho = json.load(file)
    desempenho.append({
        'usuario': usuario,
        'curso': curso,
        'acertos': acertos,
        'data': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    with open(DESEMPENHO_FILE, 'w') as file:
        json.dump(desempenho, file, indent=4)

def exibir_cursos():
    while True:
        print("\n--- Cursos Disponíveis ---")
        print("1. Pensamento Lógico Computacional")
        print("2. Programação em Python")
        print("3. Segurança Digital")
        print("0. Voltar ao menu anterior")
        escolha = input("Escolha um curso: ")

        if escolha == '1':
            curso_logica()
        elif escolha == '2':
            curso_python()
        elif escolha == '3':
            curso_seguranca()
        elif escolha == '0':
            break
        else:
            print("Opção inválida.")
            
def curso_logica():
    print("\n--- Pensamento Lógico Computacional ---")
    acertos = 0

    print("1) Qual estrutura usamos para repetir ações?")
    r1 = input("(a) if (b) for (c) print: ").lower()
    if r1 == 'b':
        acertos += 1

    print("2) Qual estrutura usamos para tomar decisões?")
    r2 = input("(a) if (b) while (c) print: ").lower()
    if r2 == 'a':
        acertos += 1

    print("3) Qual dessas é uma estrutura de repetição?")
    r3 = input("(a) else (b) for (c) def: ").lower()
    if r3 == 'b':
        acertos += 1

    print(f"\nVocê acertou {acertos} de 3 perguntas.")
    salvar_desempenho(usuario, "Lógica Computacional", acertos)


def curso_python():
    print("\n--- Programação em Python ---")
    acertos = 0

    print("1) Qual comando usamos para mostrar algo na tela?")
    r1 = input("(a) input (b) print (c) def: ").lower()
    if r1 == 'b':
        acertos += 1

    print("2) Qual símbolo usamos para comentários?")
    r2 = input("(a) // (b) <!-- (c) #: ").lower()
    if r2 == 'c':
        acertos += 1

    print("3) Qual tipo representa números inteiros?")
    r3 = input("(a) str (b) int (c) float: ").lower()
    if r3 == 'b':
        acertos += 1

    print(f"\nVocê acertou {acertos} de 3 perguntas.")
    salvar_desempenho(usuario, "Python", acertos)


def curso_seguranca():
    print("\n--- Segurança Digital ---")
    acertos = 0

    print("1) Qual dessas é uma boa prática de segurança?")
    r1 = input("(a) Usar a mesma senha (b) Compartilhar senha (c) Usar senhas fortes: ").lower()
    if r1 == 'c':
        acertos += 1

    print("2) O que é phishing?")
    r2 = input("(a) Um tipo de vírus (b) Um golpe por e-mail (c) Um antivírus: ").lower()
    if r2 == 'b':
        acertos += 1

    print("3) O que é backup?")
    r3 = input("(a) Atualizar o sistema (b) Salvar cópia dos dados (c) Apagar arquivos: ").lower()
    if r3 == 'b':
        acertos += 1

    print(f"\nVocê acertou {acertos} de 3 perguntas.")
    salvar_desempenho(usuario, "Segurança Digital", acertos)


def main():
    while True:
        print("Bem-vindo! Por favor, faça login ou registre-se.")
        print("1. Login")
        print("2. Registrar-se")
        print("3. Sair")
        opcao = input("Escolha uma opção: ")

        login_time = None

        if opcao == '1':
            global usuario
            usuario = input("Usuário: ")
            senha = getpass.getpass("Senha: ")
            if not verificar_login(usuario, senha):
                print("Usuário ou senha incorretos.")
                continue
            incrementar_acessos(usuario)
            tipo_usuario = obter_tipo_usuario(usuario)
            login_time = time.time()
            print("Dica de segurança: Nunca compartilhe sua senha com ninguém. Este sistema não solicita senhas por e-mail ou mensagens.")


        elif opcao == '2':
            usuario = input("Novo usuário: ")
            senha = input("Nova senha: ")
            nome = input("Nome: ")
            idade = int(input("Idade: "))
            tipo = input("Tipo de usuário (admin/aluno): ").lower()
            if tipo not in ['admin', 'aluno']:
                tipo = 'aluno'
            registrar_usuario_com_dados(usuario, senha, nome, idade, tipo)
            print("Usuário registrado com sucesso!")
            continue


        elif opcao == '3':
            print("Encerrando o programa. Até logo!")
            return # encerrando a função main

        else:
            print("Opção inválida.")
            continue

        try:
            while True:
                if tipo_usuario == 'admin':
                    print("\n1. Cadastrar aluno")
                    print("2. Consultar dados")
                    print("3. Análise estatística")
                    print("4. Criar gráfico")
                    print("5. Backup")
                    print("6. Acessar cursos")
                    print("7. Excluir usuário")
                    print("8. Sair")
                else:
                    print("\n1. Backup")
                    print("2. Acessar cursos")
                    print("3. Excluir minha conta")
                    print("4. Sair")

                opcao = input("Escolha uma opção: ")

                if tipo_usuario == 'admin':
                    if opcao == '1':
                        nome = input("Nome do aluno: ")
                        idade = int(input("Idade: "))
                        aluno_usuario = input("Usuário do aluno: ")
                        aluno_senha = input("Senha do aluno: ")
                        registrar_usuario_com_dados(aluno_usuario, aluno_senha, nome, idade)
                        print("Aluno cadastrado com sucesso!")
                    elif opcao == '2':
                        print("Aviso: Os dados exibidos estão em conformidade com a LGPD e são utilizados apenas para fins acadêmicos.")
                        dados = carregar_dados()
                        for i, d in enumerate(dados, start=1):
                            d['nome'] = f"Usuário {i}"
                            d['senha'] = "Dado protegido pela LGPD"
                        print("Dados:", dados)
                    elif opcao == '3':
                        dados = carregar_dados()
                        idades = [d['idade'] for d in dados if 'idade' in d]
                        if idades:
                            media, moda, mediana = analise_estatistica(idades)
                            print(f"Média: {media}, Moda: {moda}, Mediana: {mediana}")
                        else:
                            print("Sem dados suficientes.")
                    elif opcao == '4':
                        dados = carregar_dados()

                        idades = {}
                        acessos = {}
                        tempo_uso = {}

                        for i, d in enumerate(dados):
                            nome = f"Usuário {i+1}"
                            if 'idade' in d:
                                idades[nome] = d['idade']
                            if 'acessos' in d:
                                acessos[nome] = d['acessos']
                            if 'tempo_uso' in d:
                                tempo_uso[nome] = d['tempo_uso']

                        exibir_grafico(idades, "Idades dos Usuários")
                        exibir_grafico(acessos, "Número de Acessos")
                        exibir_grafico_tempo(tempo_uso, "Tempo Médio de Uso")
                        grafico_desempenho_por_curso()
                        grafico_alunos_por_curso()

                    elif opcao == '5':
                        criar_backup()
                    elif opcao == '6':
                        exibir_cursos()
                    elif opcao == '7':
                        usuarios = carregar_usuarios()
                        if not usuarios:
                            print("Nenhum usuário cadastrado.")
                        else:
                            print("Usuários disponíveis para exclusão:")
                            for nome in usuarios:
                                print(f"- {nome}")
                            print("0 - Voltar ao menu anterior")
                            usuario_excluir = input("Digite o nome do usuário que deseja excluir ou 0 para voltar: ")
                            if usuario_excluir == '0':
                                print("Voltando ao menu principal...")
                            elif usuario_excluir in usuarios:
                                excluir_usuario(usuario_excluir)
                    elif opcao == '8':
                        print("Saindo...")
                        break
                    else:
                        print("Opção inválida.")
                else:
                    if opcao == '1':
                        criar_backup()
                    elif opcao == '2':
                        exibir_cursos()
                    elif opcao == '3':
                        confirmar = input("Tem certeza que deseja excluir sua conta? (s/n): ").lower()
                        if confirmar == 's':
                            excluir_usuario(usuario)
                            print("Sua conta foi excluída. Encerrando sessão...")
                            break
                    elif opcao == '4':
                        print("Saindo...")
                        break
                    else:
                        print("Opção inválida.")
        finally:
            if login_time:
                logout_time = time.time()
                tempo_uso = (logout_time - login_time) / 3600
                atualizar_tempo_uso(usuario, tempo_uso)

if __name__ == '__main__':
    main()
