from db import engine, Base
from models import Message  # sadece import etmemiz yeterli

Base.metadata.create_all(bind=engine)
print("OK: tables created")