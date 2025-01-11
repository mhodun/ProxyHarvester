from sqlalchemy import Column, String, Integer, Date
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


# Define the Proxies table
class Proxy(Base):
    __tablename__ = 'proxies'

    host = Column(String, primary_key=True, nullable=False)
    port = Column(Integer, nullable=False)
    country_code = Column(String(3), nullable=False)
    source = Column(String(40), nullable=False)
    date_added = Column(Date, nullable=False)
