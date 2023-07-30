from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from sqlalchemy import create_engine, Column, Integer, String, LargeBinary, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
from cryptography.fernet import Fernet
from qiskit import QuantumCircuit, transpile, assemble, Aer
import secrets

app = FastAPI()

DATABASE_URL = "sqlite:///encrypted_files.db"
engine = create_engine(DATABASE_URL)
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class EncryptedFile(Base):
    __tablename__ = "encrypted_files"

    id = Column(Integer, primary_key=True, index=True)
    file_name = Column(String, index=True)
    encrypted_data = Column(LargeBinary)
    password_hash = Column(String)
    is_encrypted = Column(Boolean, default=False)


Base.metadata.create_all(bind=engine)


def generate_key(qrng_seed: int) -> bytes:
    # Initialize QRNG with seed
    qrng = QuantumCircuit(1, 1)
    qrng.initialize([0, 1], 0)
    qrng.reset(0)
    qrng.initialize([0, 1], 0)
    qrng.measure(0, 0)

    simulator = Aer.get_backend('qasm_simulator')
    qrng_job = assemble(transpile(qrng, simulator), shots=1, seed_simulator=qrng_seed)
    qrng_result = simulator.run(qrng_job).result()

    random_bit = int(qrng_result.get_counts(qrng).most_frequent()[0])

    # Generate random key using secrets module
    random_key = secrets.token_bytes(32)
    random_key = bytearray(random_key)

    # XOR the random key with the QRNG output to generate the final key
    for i in range(len(random_key)):
        random_key[i] ^= random_bit

    return bytes(random_key)


def encrypt_file(file_path: str, key: bytes, password: str) -> bytes:
    with open(file_path, 'rb') as file:
        data = file.read()

    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)

    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    return encrypted_data


def decrypt_file(file_path: str, key: bytes) -> bytes:
    with open(file_path, 'rb') as encrypted_file:
        encrypted_data = encrypted_file.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    return decrypted_data


@app.post("/encrypt/")
def encrypt_pdf(
        pdf_file: UploadFile = File(...),
        password: str = Form(...),
):
    qrng_seed = int.from_bytes(password.encode(), 'big')
    key = generate_key(qrng_seed)

    encrypted_data = encrypt_file(pdf_file.filename, key, password)

    db_session = SessionLocal()
    encrypted_file = EncryptedFile(file_name=pdf_file.filename, encrypted_data=encrypted_data, password_hash=password)
    db_session.add(encrypted_file)
    db_session.commit()
    db_session.close()

    return {"message": "Encryption successful!"}


@app.post("/decrypt/")
def decrypt_pdf(
        file_name: str = Form(...),
        password: str = Form(...),
):
    db_session = SessionLocal()
    encrypted_file = db_session.query(EncryptedFile).filter_by(file_name=file_name).first()

    if not encrypted_file:
        raise HTTPException(status_code=404, detail="File not found")

    qrng_seed = int.from_bytes(password.encode(), 'big')
    key = generate_key(qrng_seed)

    decrypted_data = decrypt_file(file_name, key)

    db_session.close()

    return decrypted_data
