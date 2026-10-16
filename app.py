import csv
import io
import os
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, Response, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import extract
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

# Carrega as variáveis do arquivo .env (se existir)
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'chave-secreta-para-sessoes-financeiras-123')

# --- CONFIGURAÇÃO DO BANCO DE DADOS (Compatível com Vercel) ---
IS_VERCEL = os.getenv('VERCEL') == '1'

if IS_VERCEL:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/database.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIGURAÇÃO DO FLASK-MAIL (Com fallback para Gmail) ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'fabianosant994@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD', 'prkoknjlihvmgnpw')
app.config['MAIL_DEFAULT_SENDER'] = ('Org Money', app.config['MAIL_USERNAME'])

db = SQLAlchemy(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar a página.'
login_manager.login_message_category = 'danger'

# --- HELPER DE CONVERSÃO DE MONETÁRIO BRL PARA FLOAT ---

def converter_brl_para_float(valor_input):
    if not valor_input:
        return 0.0
    if isinstance(valor_input, (int, float)):
        return float(valor_input)

    valor_limpo = str(valor_input).replace('R$', '').replace('.', '').replace(',', '.').strip()
    try:
        return float(valor_limpo)
    except ValueError:
        return 0.0

# --- MODELOS DO BANCO DE DADOS ---

class Usuario(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)

    transacoes = db.relationship('Transacao', backref='usuario', lazy=True, cascade="all, delete-orphan")
    configuracoes = db.relationship('Configuracao', backref='usuario', lazy=True, cascade="all, delete-orphan")

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def checar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)


class Transacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(100), nullable=False)
    valor = db.Column(db.Float, nullable=False)
    tipo = db.Column(db.String(10), nullable=False)  # 'receita' ou 'despesa'
    categoria = db.Column(db.String(50), nullable=False)
    data = db.Column(db.DateTime, default=datetime.utcnow)

    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)


class Configuracao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receita_fixa = db.Column(db.Float, default=0.0)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))


# Criação das tabelas no contexto correto da aplicação
with app.app_context():
    db.create_all()

# --- FILTRO DE FORMATAÇÃO DE MOEDA (BRL) ---

@app.template_filter('formato_brl')
def formato_brl(valor):
    if valor is None:
        valor = 0.0
    return f"{valor:,.2f}".replace(',', 'X').replace('.', ',').replace('X', '.')

# --- SPLASH & AUTENTICAÇÃO ---

@app.route('/')
def splash():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    return render_template('splash.html')


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        senha = request.form.get('senha')

        usuario_existente = Usuario.query.filter_by(email=email).first()
        if usuario_existente:
            flash('E-mail já cadastrado. Faça login ou use outro e-mail.', 'danger')
            return redirect(url_for('cadastro'))

        novo_usuario = Usuario(nome=nome, email=email)
        novo_usuario.set_senha(senha)

        db.session.add(novo_usuario)
        db.session.commit()

        flash('Conta criada com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))

    return render_template('cadastro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        senha = request.form.get('senha')

        usuario = Usuario.query.filter_by(email=email).first()

        if usuario and usuario.checar_senha(senha):
            login_user(usuario)
            return redirect(url_for('index'))
        else:
            flash('E-mail ou senha incorretos.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Você saiu do sistema.', 'success')
    return redirect(url_for('login'))

# --- ROTAS DE RECUPERAÇÃO DE SENHA ---

@app.route('/esqueci_senha', methods=['GET', 'POST'])
def esqueci_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            token = serializer.dumps(email, salt='recuperacao-senha-salt')
            link = url_for('redefinir_senha', token=token, _external=True)

            msg = Message('Org Money - Redefinição de Senha', recipients=[email])
            msg.body = f'''Olá, {usuario.nome}!

Você solicitou a redefinição de senha da sua conta no Org Money.
Clique no link a seguir para cadastrar uma nova senha:

{link}

Se você não solicitou essa alteração, ignore este e-mail. O link expira em 30 minutos.
'''
            try:
                mail.send(msg)
                flash('E-mail de redefinição enviado! Verifique sua caixa de entrada.', 'success')
            except Exception as e:
                print(f"ERRO SMTP: {e}")
                flash('Erro ao enviar e-mail. Verifique as configurações de SMTP.', 'danger')
        else:
            flash('Se o e-mail estiver cadastrado, você receberá o link de redefinição.', 'info')

        return redirect(url_for('login'))

    return render_template('esqueci_senha.html')


@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    try:
        email = serializer.loads(token, salt='recuperacao-senha-salt', max_age=1800)
    except (SignatureExpired, BadTimeSignature):
        flash('O link de redefinição é inválido ou expirou. Solicite um novo.', 'danger')
        return redirect(url_for('esqueci_senha'))

    usuario = Usuario.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        nova_senha = request.form.get('senha')
        usuario.set_senha(nova_senha)
        db.session.commit()

        flash('Sua senha foi redefinida com sucesso! Faça login com a nova senha.', 'success')
        return redirect(url_for('login'))

    return render_template('redefinir_senha.html', token=token)

# --- ROTAS PRINCIPAIS DO PAINEL ---

@app.route('/dashboard')
@login_required
def index():
    hoje = datetime.now()
    mes_selecionado = request.args.get('mes', type=int, default=hoje.month)
    ano_selecionado = request.args.get('ano', type=int, default=hoje.year)

    config = Configuracao.query.filter_by(usuario_id=current_user.id).first()
    if not config:
        config = Configuracao(receita_fixa=0.0, usuario_id=current_user.id)
        db.session.add(config)
        db.session.commit()

    transacoes = Transacao.query.filter(
        Transacao.usuario_id == current_user.id,
        extract('month', Transacao.data) == mes_selecionado,
        extract('year', Transacao.data) == ano_selecionado
    ).order_by(Transacao.data.desc()).all()

    receitas_transacoes = sum(t.valor for t in transacoes if t.tipo == 'receita')
    total_receitas = config.receita_fixa + receitas_transacoes
    total_despesas = sum(t.valor for t in transacoes if t.tipo == 'despesa')
    saldo = total_receitas - total_despesas

    categorias = {}
    for t in transacoes:
        if t.tipo == 'despesa':
            categorias[t.categoria] = categorias.get(t.categoria, 0) + t.valor

    return render_template(
        'index.html',
        transacoes=transacoes,
        saldo=saldo,
        receitas=total_receitas,
        despesas=total_despesas,
        receita_fixa=config.receita_fixa,
        categorias=categorias,
        mes_atual=mes_selecionado,
        ano_atual=ano_selecionado,
        usuario_nome=current_user.nome
    )


@app.route('/adicionar', methods=['POST'])
@login_required
def adicionar():
    descricao = request.form.get('descricao')
    valor = converter_brl_para_float(request.form.get('valor'))
    tipo = request.form.get('tipo')
    categoria = request.form.get('categoria')

    nova_transacao = Transacao(
        descricao=descricao,
        valor=valor,
        tipo=tipo,
        categoria=categoria,
        usuario_id=current_user.id
    )
    db.session.add(nova_transacao)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/definir_receita', methods=['POST'])
@login_required
def definir_receita():
    nova_receita = converter_brl_para_float(request.form.get('receita_fixa'))
    config = Configuracao.query.filter_by(usuario_id=current_user.id).first()
    if not config:
        config = Configuracao(receita_fixa=nova_receita, usuario_id=current_user.id)
        db.session.add(config)
    else:
        config.receita_fixa = nova_receita

    db.session.commit()
    return redirect(url_for('index'))


@app.route('/deletar/<int:id>')
@login_required
def deletar(id):
    transacao = Transacao.query.filter_by(id=id, usuario_id=current_user.id).first_or_404()
    db.session.delete(transacao)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar(id):
    transacao = Transacao.query.filter_by(id=id, usuario_id=current_user.id).first_or_404()
    if request.method == 'POST':
        transacao.descricao = request.form.get('descricao')
        transacao.valor = converter_brl_para_float(request.form.get('valor'))
        transacao.tipo = request.form.get('tipo')
        transacao.categoria = request.form.get('categoria')

        db.session.commit()
        return redirect(url_for('index'))

    return render_template('editar.html', transacao=transacao)


@app.route('/exportar_csv')
@login_required
def exportar_csv():
    hoje = datetime.now()
    mes_selecionado = request.args.get('mes', type=int, default=hoje.month)
    ano_selecionado = request.args.get('ano', type=int, default=hoje.year)

    transacoes = Transacao.query.filter(
        Transacao.usuario_id == current_user.id,
        extract('month', Transacao.data) == mes_selecionado,
        extract('year', Transacao.data) == ano_selecionado
    ).order_by(Transacao.data.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')

    writer.writerow(['ID', 'Data', 'Descrição', 'Tipo', 'Categoria', 'Valor (R$)'])

    for t in transacoes:
        writer.writerow([
            t.id,
            t.data.strftime('%d/%m/%Y'),
            t.descricao,
            t.tipo.capitalize(),
            t.categoria,
            f"{t.valor:.2f}".replace('.', ',')
        ])

    output.seek(0)
    filename = f"transacoes_{mes_selecionado:02d}_{ano_selecionado}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8-sig",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route('/dicas')
@login_required
def dicas():
    return render_template('dicas.html')


if __name__ == '__main__':
    app.run(debug=True)