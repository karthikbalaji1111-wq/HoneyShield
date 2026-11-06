import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.tenant import Tenant
from app.models.user import User
from app.models.honey_token import HoneyToken
from app.models.enums import Role
from app.core.security import get_password_hash, create_access_token
import uuid

engine = create_engine("postgresql+psycopg2://honeyshield:secure_prod_password_123@postgres:5432/honeyshield_dev")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def setup_db():
    db = SessionLocal()
    try:
        tenant_name = f"Tenant {uuid.uuid4().hex[:8]}"
        tenant = Tenant(name=tenant_name, slug=tenant_name.lower().replace(" ", "-"))
        db.add(tenant)
        db.commit()
        db.refresh(tenant)
        
        user = User(
            email=f"admin_{uuid.uuid4().hex[:8]}@test.com",
            hashed_password=get_password_hash("password123"),
            tenant_id=tenant.id,
            role=Role.TENANT_ADMIN
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        ht_val = f"ht_{uuid.uuid4().hex[:8]}"
        ht = HoneyToken(
            name="Test HT",
            tenant_id=tenant.id,
            token_value=ht_val,
            created_by_id=user.id,
            token_type="URL"
        )
        db.add(ht)
        db.commit()
            
        token = create_access_token(user.id, tenant.id)
        print(f"{token} {ht_val}")
    finally:
        db.close()

if __name__ == "__main__":
    setup_db()
