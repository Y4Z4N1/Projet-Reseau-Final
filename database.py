import mysql.connector
import bcrypt


class Database:
    @staticmethod
    def get_db_connection():
        return mysql.connector.connect(
            host="localhost", 
            user="root",
            password="",
            database="FINDMYIP"
        )
    @staticmethod
    def verifier_login(username , password):
        try :
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            query = "SELECT passwordUser  , role FROM userInfo WHERE nameUser = %s"
            
            cursor.execute(query, (username,))
            result = cursor.fetchone()
            hashed_from_db = result[0]
            role = result[1]

            if result:
                hashed_from_db = result[0]
                if isinstance(hashed_from_db, str):
                    hashed_from_db = hashed_from_db.encode('utf-8')
                
                if(bcrypt.checkpw(password.encode('utf-8'), hashed_from_db)):
                    return role
            return False
        except Exception as e:
            print(f"erreur de connexion: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()
                cursor.close()
                
    @staticmethod
    def enregister_user(username , password):
        try : 
            conn = Database.get_db_connection()
            cursor = conn.cursor()
            
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
            
            query = "INSERT INTO userInfo (nameUser, passwordUser) VALUES (%s, %s)"
            cursor.execute(query, (username, hashed_password))
            conn.commit()
            return True
        except Exception as e:
            print(f"erreur d'enregistrement: {e}")
            return False
        finally:
            if 'conn' in locals() and conn.is_connected():
                conn.close()
                cursor.close()
