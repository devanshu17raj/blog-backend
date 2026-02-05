from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from bson import ObjectId 
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi import Depends
from typing import List, Optional

from dotenv import load_dotenv
import os
from typing import List

load_dotenv()  # <--- THIS IS THE CRITICAL MISSING LINE



app = FastAPI()

# Enable React to talk to Python
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database Connection
MONGO_URL = os.getenv("MONGODB_URL")
print("Connecting to:", MONGO_URL) 
client = AsyncIOMotorClient(MONGO_URL)
db = client.blog_db
collection = db.posts

# --- SECURITY SETUP (Paste after app = FastAPI) ---
SECRET_KEY = "supersecretkey" # In real life, hide this!
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Data Model
class Post(BaseModel):
    title: str
    content: str
    author: str
    comments: List[str] = []
    likes: int = 0
    image_url: Optional[str] = None
    created_at: Optional[datetime] = None
    
# 1. HELPER: Hash a password (turn "12345" into "fs897sfd8...")
def get_password_hash(password):
    return pwd_context.hash(password)

# 2. HELPER: Check a password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# 3. HELPER: Create a Token (The digital ID card)
def create_access_token(username: str):
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode = {"sub": username, "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- NEW USER MODEL ---
class User(BaseModel):
    username: str
    password: str    



# 1. READ (Get posts - now with Search!)
@app.get("/posts")
async def get_posts(q: str = None):
    if q:
        # Search for titles that contain 'q' (case-insensitive)
        query = {"title": {"$regex": q, "$options": "i"}}
        posts = await collection.find(query).to_list(100)
    else:
        # If no search, get all posts
        posts = await collection.find().to_list(100)
        
    # Convert _id to string
    for post in posts:
        post["_id"] = str(post["_id"])
    return posts

# 2. CREATE (Add a post)
@app.post("/posts")
async def create_post(post: Post):
    post_dict = post.dict()
    
    # This line injects the current time!
    post_dict['created_at'] = datetime.now() 
    
    new_post = await collection.insert_one(post_dict)
    return {"message": "Post created", "id": str(new_post.inserted_id)}

# 3. DELETE (Remove a post) <--- THIS IS THE NEW PART
@app.delete("/posts/{id}")
async def delete_post(id: str):
    await collection.delete_one({"_id": ObjectId(id)})
    return {"message": "Post deleted"}


# 4. UPDATE (Edit a post)
@app.put("/posts/{id}")
async def update_post(id: str, post: Post):
    await collection.update_one({"_id": ObjectId(id)}, {"$set": post.dict()})
    return {"message": "Post updated"}


# 2.5 READ ONE (Get a specific post by ID)
@app.get("/posts/{id}")
async def get_single_post(id: str):
    post = await collection.find_one({"_id": ObjectId(id)})
    if post:
        post["_id"] = str(post["_id"])
        return post
    raise HTTPException(status_code=404, detail="Post not found")

# 5. ADD COMMENT
class CommentBody(BaseModel):
    text: str

@app.post("/posts/{id}/comments")
async def add_comment(id: str, comment: CommentBody):
    await collection.update_one(
        {"_id": ObjectId(id)},
        {"$push": {"comments": comment.text}} # $push adds to the list
    )
    return {"message": "Comment added"}

# 6. ADD LIKE (Increment the counter)
@app.post("/posts/{id}/like")
async def like_post(id: str):
    await collection.update_one(
        {"_id": ObjectId(id)},
        {"$inc": {"likes": 1}} # $inc means "increase by"
    )
    return {"message": "Post liked"}

# --- ENDPOINT 1: REGISTER (Sign Up) ---
@app.post("/register")
async def register(user: User):
    # Check if user exists
    if await db.users.find_one({"username": user.username}):
        raise HTTPException(status_code=400, detail="Username taken")
    
    # Hash password and save
    user_dict = user.dict()
    user_dict["password"] = get_password_hash(user.password)
    await db.users.insert_one(user_dict)
    return {"message": "User created!"}

# --- ENDPOINT 2: LOGIN (Sign In) ---
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await db.users.find_one({"username": form_data.username})
    
    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect password")
    
    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer"}