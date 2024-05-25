import bcrypt


passw = "asd".encode('utf-8')
salt = bcrypt.gensalt()
s = str(salt)
a = bcrypt.hashpw(passw,s.encode('utf-8'))
print(a)

print(bcrypt.checkpw(passw,a))