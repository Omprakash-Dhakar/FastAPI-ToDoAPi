# # Install dependencies
# !pip install fastapi
# !pip install mysql-connector-python
# !pip install pydantic
# !pip install jwt

# Import libraries
import mysql.connector
from jose import JWTError, jwt
from fastapi import FastAPI, HTTPException, Header, Depends,status
from pydantic import BaseModel
from passlib.context import CryptContext 
from typing import Union
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta


SECRET_KEY = "bc30946a64fb72b96f01964a7e85e5f7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    }
}

# Connect to the database
cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
cursor = cnx.cursor()

# Create the to-do list table
table = '''
CREATE TABLE IF NOT EXISTS todo_items (
    id INTEGER PRIMARY KEY AUTO_INCREMENT,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL
)
'''
cursor.execute(table)
cnx.commit()
cursor.close()
cnx.close()

# Define the to-do list item model
class Item(BaseModel):
    title: str
    description: str
    status: str

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

        
# Retrieve all to-do list items
def read_items():
    # Connect to the database
    cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
    cursor = cnx.cursor()

    # Retrieve all to-do list items
    query = '''
    SELECT * FROM todo_items
    '''
    cursor.execute(query)
    items = cursor.fetchall()

    # Close the connection
    cursor.close()
    cnx.close()

    return items

# Retrieve a specific to-do list item
def read_item(id):
    # Connect to the database
    cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
    cursor = cnx.cursor()

    # Retrieve the to-do list item
    query = '''
    SELECT * FROM todo_items WHERE id = %s
    '''
    cursor.execute(query, (id,))
    item = cursor.fetchone()

    # Close the connection
    cursor.close()
    cnx.close()

    return item

# Create a new to-do list item
def create_item(item: Item):
    # Connect to the database
    cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
    cursor = cnx.cursor()

    # Insert the new to-do list item
    query = '''
    INSERT INTO todo_items (title, description, status, created_at)
    VALUES (%s, %s, %s, NOW())
    '''
    cursor.execute(query, (item.title, item.description, item.status))
    cnx.commit()

    # Close the connection
    cursor.close()
    cnx.close()

# Update an existing to-do list item
def update_item(id, item: Item):
    # Connect to the database
    cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
    cursor = cnx.cursor()

    # Update the to-do list item
    query = '''
    UPDATE todo_items
    SET title = %s, description = %s, status = %s
    WHERE id = %s
    '''
    cursor.execute(query, (item.title, item.description, item.status, id))
    cnx.commit()

    # Close the connection
    cursor.close()
    cnx.close()

# Delete an existing to-do list item
def delete_item(id):
    # Connect to the database
    cnx =  mysql.connector.connect(user='root', password='password', host='127.0.0.1', database='ToDOList')
    cursor = cnx.cursor()

    # Delete the to-do list item
    query = '''
    DELETE FROM todo_items WHERE id = %s
    '''
    cursor.execute(query, (id,))
    cnx.commit()

    # Close the connection
    cursor.close()
    cnx.close()

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Define the API endpoints
@app.post("/items")
def create_item(item: Item, current_user: OAuth2PasswordRequestForm = Depends(get_current_active_user)):
    # # Validate the JWT
    # user = authenticate_user(authorization.username)
    if current_user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Create the to-do list item
    create_item(item)
    return {"status": "success"}

@app.get("/items/{id}")
def read_item(id: int, authorization: str = Header(None)):
    # Validate the JWT
    user = authenticate_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Retrieve the to-do list item
    item = read_item(id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return item

@app.put("/items/{id}")
def update_item(id: int, item: Item, authorization: str = Header(None)):
    # Validate the JWT
    user = authenticate_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Update the to-do list item
    update_item(id, item)
    return {"status": "success"}

@app.delete("/items/{id}")
def delete_item(id: int, authorization: str = Header(None)):
    # Validate the JWT
    user = authenticate_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Delete the to-do list item
    delete_item(id)
    return {"status": "success"}

@app.post("/logout")
def logout(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Validate the JWT
    user = authenticate_user(authorization)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Invalidate the JWT
    # Note: In a real application, you would need to store the JWT in a database or cache and mark it as invalid.
    # For simplicity, we will just return a success message here.
    return {"status": "success"}

