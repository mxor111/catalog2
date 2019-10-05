#!/usr/bin/python 3
#seup database

import os
import sys
from sqlalchemy import Column, ForeginKey, Integer, String
from sqlalchemy ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemyimport create_engine

Base = declarative_base() # correspond to table in database
#create classes to correspond with the tables
class User(Base):
    """class to create the table user"""

    __tablename__ = "user"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False))
    
class Category(Base):
    """class to create table category"""

    __tablename__ = "category"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        """return object data in easy format"""

        return {
            'id': self.id,
            'name': self.name,
            'user_id': self.user_id
        }

class Item(Base):
    """class to create the table item"""

    __tablename__ = "item"


    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    description = Column(String(250))
    price = Column(String(8))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)


    @property
    def serialize(self):
        """return object data in easy format"""

        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'user_id': self.user_id,
            'category_id': self.category_id
        }

#add at end
engine - create_engine(sqlite:///itemcatalog.db)
# creates a new database
Base.metadata.create_all(engine)




Base.metadata.create_all(engine)
#goes into database and add class we will create
