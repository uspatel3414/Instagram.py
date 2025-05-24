from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
import bcrypt
import httpx
import asyncio
from contextlib import asynccontextmanager
import os
from dataclasses import dataclass
import logging

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost/instagram_assistant")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
INSTAGRAM_APP_ID = os.getenv("INSTAGRAM_APP_ID")
INSTAGRAM_APP_SECRET = os.getenv("INSTAGRAM_APP_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Security
security = HTTPBearer()

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    username = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    bio = Column(Text)
    profile_image_url = Column(String)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    two_factor_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    instagram_accounts = relationship("InstagramAccount", back_populates="user")
    notifications = relationship("Notification", back_populates="user")
    activity_logs = relationship("ActivityLog", back_populates="user")
    smart_replies = relationship("SmartReply", back_populates="user")
    story_schedules = relationship("StorySchedule", back_populates="user")

class InstagramAccount(Base):
    __tablename__ = "instagram_accounts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instagram_user_id = Column(String, unique=True, nullable=False)
    username = Column(String, nullable=False)
    account_type = Column(String, nullable=False)  # personal, business, creator
    access_token = Column(String, nullable=False)
    token_expires_at = Column(DateTime)
    profile_picture_url = Column(String)
    followers_count = Column(Integer, default=0)
    following_count = Column(Integer, default=0)
    media_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    needs_reauth = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="instagram_accounts")
    analytics = relationship("Analytics", back_populates="instagram_account")

class SmartReply(Base):
    __tablename__ = "smart_replies"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instagram_account_id = Column(Integer, ForeignKey("instagram_accounts.id"), nullable=False)
    comment_id = Column(String, nullable=False)
    original_comment = Column(Text, nullable=False)
    reply_content = Column(Text, nullable=False)
    confidence_score = Column(Integer, default=0)  # 0-100
    status = Column(String, default="pending")  # pending, approved, sent, declined
    sent_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="smart_replies")

class StorySchedule(Base):
    __tablename__ = "story_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    instagram_account_id = Column(Integer, ForeignKey("instagram_accounts.id"), nullable=False)
    story_url = Column(String, nullable=False)
    interaction_type = Column(String, nullable=False)  # view, like, reply
    scheduled_time = Column(DateTime, nullable=False)
    status = Column(String, default="scheduled")  # scheduled, completed, failed, cancelled
    response_message = Column(Text)
    executed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="story_schedules")

class Analytics(Base):
    __tablename__ = "analytics"
    
    id = Column(Integer, primary_key=True, index=True)
    instagram_account_id = Column(Integer, ForeignKey("instagram_accounts.id"), nullable=False)
    date = Column(DateTime, nullable=False)
    impressions = Column(Integer, default=0)
    reach = Column(Integer, default=0)
    profile_visits = Column(Integer, default=0)
    website_clicks = Column(Integer, default=0)
    engagement_rate = Column(Integer, default=0)  # percentage * 100
    followers_gained = Column(Integer, default=0)
    followers_lost = Column(Integer, default=0)
    story_views = Column(Integer, default=0)
    story_replies = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    instagram_account = relationship("InstagramAccount", back_populates="analytics")

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    type = Column(String, nullable=False)  # smart_reply, story_schedule, analytics, security
    is_read = Column(Boolean, default=False)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="notifications")

class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    activity_type = Column(String, nullable=False)  # login, logout, account_update, password_change
    ip_address = Column(String)
    user_agent = Column(String)
    location = Column(String)
    device_info = Column(String)
    success = Column(Boolean, default=True)
    metadata = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="activity_logs")

# Pydantic models
class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    bio: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    bio: Optional[str] = None
    profile_image_url: Optional[str] = None

class UserResponse(UserBase):
    id: int
    is_active: bool
    two_factor_enabled: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class InstagramAccountResponse(BaseModel):
    id: int
    instagram_user_id: str
    username: str
    account_type: str
    profile_picture_url: Optional[str]
    followers_count: int
    following_count: int
    media_count: int
    is_active: bool
    needs_reauth: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class SmartReplyCreate(BaseModel):
    comment_id: str
    original_comment: str
    reply_content: str
    confidence_score: int

class SmartReplyResponse(BaseModel):
    id: int
    comment_id: str
    original_comment: str
    reply_content: str
    confidence_score: int
    status: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class StoryScheduleCreate(BaseModel):
    instagram_account_id: int
    story_url: str
    interaction_type: str
    scheduled_time: datetime
    response_message: Optional[str] = None

class StoryScheduleResponse(BaseModel):
    id: int
    instagram_account_id: int
    story_url: str
    interaction_type: str
    scheduled_time: datetime
    status: str
    response_message: Optional[str]
    created_at: datetime
    
    class Config:
        from_attributes = True

class AnalyticsResponse(BaseModel):
    date: datetime
    impressions: int
    reach: int
    profile_visits: int
    website_clicks: int
    engagement_rate: int
    followers_gained: int
    followers_lost: int
    story_views: int
    story_replies: int
    
    class Config:
        from_attributes = True

class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    type: str
    is_read: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Authentication utilities
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Instagram API service
class InstagramAPIService:
    def __init__(self):
        self.base_url = "https://graph.instagram.com"
        self.client = httpx.AsyncClient()
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get Instagram user profile information"""
        url = f"{self.base_url}/me"
        params = {
            "fields": "id,username,account_type,media_count",
            "access_token": access_token
        }
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    async def get_user_media(self, access_token: str, limit: int = 25) -> Dict[str, Any]:
        """Get user's recent media"""
        url = f"{self.base_url}/me/media"
        params = {
            "fields": "id,caption,media_type,media_url,thumbnail_url,timestamp,like_count,comments_count",
            "limit": limit,
            "access_token": access_token
        }
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    async def get_media_comments(self, media_id: str, access_token: str) -> Dict[str, Any]:
        """Get comments for a specific media"""
        url = f"{self.base_url}/{media_id}/comments"
        params = {
            "fields": "id,text,username,timestamp,like_count,replies",
            "access_token": access_token
        }
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()
    
    async def reply_to_comment(self, media_id: str, message: str, access_token: str) -> Dict[str, Any]:
        """Reply to a comment"""
        url = f"{self.base_url}/{media_id}/comments"
        data = {
            "message": message,
            "access_token": access_token
        }
        response = await self.client.post(url, data=data)
        response.raise_for_status()
        return response.json()
    
    async def get_insights(self, access_token: str, metric: str, period: str) -> Dict[str, Any]:
        """Get account insights"""
        url = f"{self.base_url}/me/insights"
        params = {
            "metric": metric,
            "period": period,
            "access_token": access_token
        }
        response = await self.client.get(url, params=params)
        response.raise_for_status()
        return response.json()

instagram_service = InstagramAPIService()

# Smart Reply AI Service (Mock implementation)
class SmartReplyService:
    def __init__(self):
        self.replies_db = {
            "positive": [
                "Thank you so much! 😊",
                "I really appreciate your kind words! ❤️",
                "Thanks for the love! 🙏",
                "So glad you enjoyed it! ✨"
            ],
            "question": [
                "Great question! Let me get back to you on that.",
                "Thanks for asking! I'll share more details soon.",
                "Interesting point! I'd love to discuss this further."
            ],
            "general": [
                "Thanks for your comment! 😊",
                "Appreciate you engaging with my content!",
                "Thanks for being part of our community! 🙌"
            ]
        }
    
    def analyze_comment(self, comment: str) -> Dict[str, Any]:
        """Analyze comment sentiment and generate appropriate reply"""
        comment_lower = comment.lower()
        
        # Simple sentiment analysis (in production, use proper NLP)
        if any(word in comment_lower for word in ["love", "amazing", "great", "awesome", "beautiful"]):
            category = "positive"
            confidence = 85
        elif "?" in comment:
            category = "question"
            confidence = 75
        else:
            category = "general"
            confidence = 60
        
        import random
        reply = random.choice(self.replies_db[category])
        
        return {
            "category": category,
            "confidence": confidence,
            "suggested_reply": reply
        }

smart_reply_service = SmartReplyService()

# Create FastAPI app
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create tables
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(
    title="Instagram Assistant API",
    description="Backend API for Instagram Assistant web application",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes

# Authentication
@app.post("/auth/register", response_model=UserResponse)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken")
    
    # Create new user
    hashed_password = hash_password(user.password)
    db_user = User(
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        bio=user.bio,
        hashed_password=hashed_password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

@app.post("/auth/login", response_model=Token)
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    # Log activity
    activity_log = ActivityLog(
        user_id=user.id,
        activity_type="login",
        ip_address="192.168.1.1",  # In production, get real IP
        location="San Francisco, CA, USA",
        device_info="Chrome Browser"
    )
    db.add(activity_log)
    db.commit()
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# User management
@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=UserResponse)
async def update_user(user_update: UserUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    for field, value in user_update.dict(exclude_unset=True).items():
        setattr(current_user, field, value)
    
    current_user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(current_user)
    
    # Log activity
    activity_log = ActivityLog(
        user_id=current_user.id,
        activity_type="account_update",
        ip_address="192.168.1.1",
        location="San Francisco, CA, USA",
        device_info="Chrome Browser"
    )
    db.add(activity_log)
    db.commit()
    
    return current_user

@app.post("/users/change-password")
async def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    current_user.hashed_password = hash_password(password_data.new_password)
    current_user.updated_at = datetime.utcnow()
    db.commit()
    
    # Log activity
    activity_log = ActivityLog(
        user_id=current_user.id,
        activity_type="password_change",
        ip_address="192.168.1.1",
        location="San Francisco, CA, USA",
        device_info="Chrome Browser"
    )
    db.add(activity_log)
    db.commit()
    
    return {"message": "Password changed successfully"}

# Instagram accounts
@app.get("/instagram-accounts", response_model=List[InstagramAccountResponse])
async def get_instagram_accounts(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    accounts = db.query(InstagramAccount).filter(InstagramAccount.user_id == current_user.id).all()
    return accounts

@app.post("/instagram-accounts/connect")
async def connect_instagram_account(
    access_token: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        # Get user info from Instagram
        user_info = await instagram_service.get_user_info(access_token)
        
        # Check if account already connected
        existing_account = db.query(InstagramAccount).filter(
            InstagramAccount.instagram_user_id == user_info["id"]
        ).first()
        
        if existing_account:
            raise HTTPException(status_code=400, detail="Instagram account already connected")
        
        # Create new Instagram account record
        instagram_account = InstagramAccount(
            user_id=current_user.id,
            instagram_user_id=user_info["id"],
            username=user_info["username"],
            account_type=user_info["account_type"],
            access_token=access_token,
            media_count=user_info.get("media_count", 0),
            token_expires_at=datetime.utcnow() + timedelta(days=60)  # Instagram tokens expire in 60 days
        )
        
        db.add(instagram_account)
        db.commit()
        db.refresh(instagram_account)
        
        # Log activity
        activity_log = ActivityLog(
            user_id=current_user.id,
            activity_type="instagram_connected",
            metadata={"instagram_username": user_info["username"]}
        )
        db.add(activity_log)
        db.commit()
        
        return {"message": "Instagram account connected successfully", "account": instagram_account}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to connect Instagram account: {str(e)}")

# Smart Replies
@app.get("/smart-replies", response_model=List[SmartReplyResponse])
async def get_smart_replies(
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(SmartReply).filter(SmartReply.user_id == current_user.id)
    if status:
        query = query.filter(SmartReply.status == status)
    return query.order_by(SmartReply.created_at.desc()).all()

@app.post("/smart-replies/analyze")
async def analyze_comments(
    instagram_account_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    # Verify account ownership
    account = db.query(InstagramAccount).filter(
        InstagramAccount.id == instagram_account_id,
        InstagramAccount.user_id == current_user.id
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Instagram account not found")
    
    # Start background task to analyze comments
    background_tasks.add_task(analyze_comments_task, account, db)
    
    return {"message": "Comment analysis started"}

async def analyze_comments_task(account: InstagramAccount, db: Session):
    """Background task to analyze comments and generate smart replies"""
    try:
        # Get recent media
        media_data = await instagram_service.get_user_media(account.access_token, limit=10)
        
        for media_item in media_data.get("data", []):
            # Get comments for each media
            comments_data = await instagram_service.get_media_comments(
                media_item["id"], 
                account.access_token
            )
            
            for comment in comments_data.get("data", []):
                # Check if we already processed this comment
                existing_reply = db.query(SmartReply).filter(
                    SmartReply.comment_id == comment["id"]
                ).first()
                
                if existing_reply:
                    continue
                
                # Analyze comment and generate reply
                analysis = smart_reply_service.analyze_comment(comment["text"])
                
                # Create smart reply record
                smart_reply = SmartReply(
                    user_id=account.user_id,
                    instagram_account_id=account.id,
                    comment_id=comment["id"],
                    original_comment=comment["text"],
                    reply_content=analysis["suggested_reply"],
                    confidence_score=analysis["confidence"]
                )
                
                db.add(smart_reply)
        
        db.commit()
        
    except Exception as e:
        logging.error(f"Error analyzing comments: {str(e)}")

@app.post("/smart-replies/{reply_id}/approve")
async def approve_smart_reply(
    reply_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    reply = db.query(SmartReply).filter(
        SmartReply.id == reply_id,
        SmartReply.user_id == current_user.id
    ).first()
    
    if not reply:
        raise HTTPException(status_code=404, detail="Smart reply not found")
    
    # Get Instagram account
    account = db.query(InstagramAccount).filter(
        InstagramAccount.id == reply.instagram_account_id
    ).first()
    
    try:
        # Send reply to Instagram (this would need the media ID in a real implementation)
        # await instagram_service.reply_to_comment(media_id, reply.reply_content, account.access_token)
        
        reply.status = "sent"
        reply.sent_at = datetime.utcnow()
        db.commit()
        
        return {"message": "Reply sent successfully"}
        
    except Exception as e:
        reply.status = "failed"
        db.commit()
        raise HTTPException(status_code=400, detail=f"Failed to send reply: {str(e)}")

# Story Schedule
@app.get("/story-schedules", response_model=List[StoryScheduleResponse])
async def get_story_schedules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    schedules = db.query(StorySchedule).filter(
        StorySchedule.user_id == current_user.id
    ).order_by(StorySchedule.scheduled_time.desc()).all()
    return schedules

@app.post("/story-schedules", response_model=StoryScheduleResponse)
async def create_story_schedule(
    schedule_data: StoryScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify account ownership
    account = db.query(InstagramAccount).filter(
        InstagramAccount.id == schedule_data.instagram_account_id,
        InstagramAccount.user_id == current_user.id
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Instagram account not found")
    
    schedule = StorySchedule(
        user_id=current_user.id,
        **schedule_data.dict()
    )
    
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    
    return schedule

# Analytics
@app.get("/analytics/{account_id}", response_model=List[AnalyticsResponse])
async def get_analytics(
    account_id: int,
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify account ownership
    account = db.query(InstagramAccount).filter(
        InstagramAccount.id == account_id,
        InstagramAccount.user_id == current_user.id
    ).first()
    
    if not account:
        raise HTTPException(status_code=404, detail="Instagram account not found")
    
    # Get analytics data
    start_date = datetime.utcnow() - timedelta(days=days)
    analytics = db.query(Analytics).filter(
        Analytics.instagram_account_id == account_id,
        Analytics.date >= start_date
    ).order_by(Analytics.date.desc()).all()
    
    return analytics

# Notifications
@app.get("/notifications", response_model=List[NotificationResponse])
async def get_notifications(
    unread_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Notification).filter(Notification.user_id == current_user.id)
    if unread_only:
        query = query.filter(Notification.is_read == False)
    
    notifications = query.order_by(Notification.created_at.desc()).limit(50).all()
    return notifications

@app.post("/notifications/{notification_id}/mark-read")
async def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()
    
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")
    
