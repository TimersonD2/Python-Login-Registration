
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash

import re	# the regex module
# create a regular expression object that we'll use later   
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

# model the class after the table from the database
class User:
    def __init__( self , data ):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @staticmethod
    def validateEmail(user):
        isValid = True
        if not EMAIL_REGEX.match(user['email']): 
            isValid = False
        return isValid

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        # make sure to call the connectToMySQL function with the schema you are targeting.
        results = connectToMySQL('login_registration_schema').query_db(query)
        # Create an empty list to append our instances of users
        users = []
        # Iterate over the db results and create instances of users with cls.
        for user in results:
            users.append( cls(user) )
        return users

    @classmethod
    def get_one(cls, data):
        query = "SELECT * FROM users where id=%(id)s;"
        results = connectToMySQL('login_registration_schema').query_db(query, data)
        if len(results) < 1:
            return False
        return cls(results[0])

    @classmethod
    def get_one_email(cls, data):
        query = "SELECT * FROM users where email=%(email)s;"
        results = connectToMySQL('login_registration_schema').query_db(query, data)
        if len(results) < 1:
            return False
        return cls(results[0])

    @classmethod
    def save(cls, data):
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        return connectToMySQL('login_registration_schema').query_db( query, data )   

    @classmethod
    def update(cls, data):
        query = "UPDATE users SET first_name=%(first_name)s, last_name=%(last_name)s, email=%(email)s, password=%(password)s, WHERE id=%(id)s;"
        return connectToMySQL('login_registration_schema').query_db( query, data )   

    @classmethod
    def delete(cls, data):
        query = "DELETE FROM users WHERE id=%(id)s"
        return connectToMySQL('login_registration_schema').query_db( query, data )   


