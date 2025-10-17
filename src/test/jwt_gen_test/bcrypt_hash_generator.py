import bcrypt

password=b"s3cr3t"

salt = bcrypt.gensalt()

print(bcrypt.hashpw(password, salt))