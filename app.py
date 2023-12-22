from flask import Flask,flash,render_template,redirect,url_for
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from forms import ProductForm, RegistrationForm, LoginForm
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user,logout_user
import os
from constants import DATABASE_URI, UPLOAD_FOLDER, LOGIN, ADMIN, ACCESS_DENIED, ADMIN_DASBOARD, CUSTOMER

app = Flask(__name__)

def configure():
    load_dotenv()

app.config['SECRET_KEY'] = os.getenv('mysecuritykey')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(255))
# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = LOGIN

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != ADMIN:
        return ACCESS_DENIED, 403
    return ADMIN_DASBOARD

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('A user with that username already exists. Please login.')
            return redirect(url_for(LOGIN))
        # If no existing user, create a new user
        hashed_password = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        # Optionally, log in the new user and redirect to the dashboard
        login_user(new_user)
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() 
    if form.validate_on_submit():
        # Logic to check if the user exists and the password is correct
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):  
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for(LOGIN))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(80), default=CUSTOMER)

    def check_password(self, password):
        return check_password_hash(self.password, password)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == ADMIN:
        return render_template('admin_dashboard.html')  # Render the admin dashboard template

    elif current_user.role == CUSTOMER:
        customer_name = current_user.username  # Example: using username as customer name
        return render_template('customer_dashboard.html', customer_name=customer_name)  # Render the customer dashboard template

    else:
        # Optional: Handle unexpected roles
        return "Unauthorized", 403


@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    if current_user.role != ADMIN:
        products = Product.query.all()
        return render_template('products.html', products=products)

    form = ProductForm()
    if form.validate_on_submit():
        product = Product(name=form.name.data, price=form.price.data)

        # Handle image upload
        if form.image.data and allowed_file(form.image.data.filename):
            filename = secure_filename(form.image.data.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.image.data.save(filepath)
            product.image_filename = filename  # Store the filename in the database

        db.session.add(product)
        db.session.commit()
        return redirect(url_for('products'))

    return render_template('products.html', form=form, products=Product.query.all())

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/update_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def update_product(product_id):
    if current_user.role != ADMIN:
        return ACCESS_DENIED, 403

    product = Product.query.get_or_404(product_id)
    form = ProductForm(obj=product)

    if form.validate_on_submit():
        
        product.name = form.name.data
        product.price = form.price.data

        # Handle image upload
        if form.image.data and allowed_file(form.image.data.filename):
            filename = secure_filename(form.image.data.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            form.image.data.save(filepath)
            product.image_filename = filename
            print("Saved image filename:", product.image_filename)  # Add this line for debugging

        db.session.add(product)
        db.session.commit()
        
        return redirect(url_for('products'))

    return render_template('update_product.html', form=form, product=product)



@app.route('/delete_product/<int:product_id>')
@login_required
def delete_product(product_id):
    if current_user.role != ADMIN:
        return ACCESS_DENIED, 403

    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    return redirect('/products')


if __name__ == '__main__':
    app.run(debug=True)
