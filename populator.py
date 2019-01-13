#!/usr/bin/env python3
from database_setup import User, Base, Item, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False})

# Bind the above engine to a session.
Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()

user1 = User(
    name='John Doe',
    email='john@doe.com',
    picture='https://picsum.photos/100'
)

session.add(user1)
session.commit()

category1 = Category(
    name='Computers',
    user=user1
)

session.add(category1)
session.commit()

item1 = Item(
    name='Atwoods law',
    description=('Any software that can be written'
                 'in JS will eventually be written in JS.'),
    category=category1,
    user=user1
)

session.add(item1)
session.commit()

item2 = Item(
    name='Brookss law',
    description='Adding manpower to a late software project makes it later.',
    category=category1,
    user=user1
)

session.add(item2)
session.commit()


category2 = Category(
    name='Management',
    user=user1
)

session.add(category2)
session.commit()

item3 = Item(
    name='Cheops law',
    description='Nothing ever gets built on schedule or within budget.',
    category=category2,
    user=user1
)

session.add(item3)
session.commit()


print('Base de datos is populated')
