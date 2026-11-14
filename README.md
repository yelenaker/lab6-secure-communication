# Лабораторна робота №6  
## Розробка розподіленої системи з шифрованим комунікаційним каналом

**Дисципліна:** Архітектура, адміністрування та безпека інформаційних мереж  
**Університет:** Харківський національний університет імені В.Н. Каразіна  
**Кафедра:** Інтелектуальних програмних систем і технологій

---

## Мета роботи

Отримання практичних навичок роботи з **асиметричним (RSA)** та **симетричним (AES)** шифруванням, а також побудова простого захищеного каналу між клієнтом і сервером.

> Це **ілюстрація** використання RSA + AES, а **не** реалізація TLS/SSL.

---

## Архітектура проєкту

```
lab6/
├── shared/                 # Спільна криптографічна логіка
│   └── crypto/
│       ├── models.py       # RsaKeys, AesKey
│       ├── rsa_service.py  # RsaService
│       └── aes_service.py  # AesService
├── server/                 # FastAPI Web API
│   ├── app/
│   │   ├── main.py
│   │   ├── api/            # crypto_keys, secure
│   │   ├── models/
│   │   └── storage/        # In-memory storage
│   ├── Dockerfile
│   └── requirements.txt
├── client/                 # Консольний клієнт
│   ├── app/main.py
│   ├── Dockerfile
│   └── requirements.txt
├── tests/                  # Unit + API tests (pytest)
├── .github/workflows/ci.yml
├── docker-compose.yml
├── requirements.txt
└── README.md
```

Спільний код (`RsaService`, `AesService`) винесено в пакет `shared`, щоб уникнути дублювання між сервером і клієнтом.

---

## Завдання 1 — RSA Web API

### Endpoints

| Method | Endpoint | Опис |
|--------|----------|------|
| `POST` | `/api/crypto-keys/generate/rsa-keys` | Генерує пару RSA-ключів, зберігає в пам’яті, повертає integer ID |
| `GET`  | `/api/crypto-keys/rsa-public-key/{id}` | Повертає public key у Base64. 404 якщо ID не існує |

### RsaService

- `generate_crypto_keys()` → `RsaKeys(public_key, private_key)`
- `encrypt(public_key, plain_text)` → Base64 ciphertext
- `decrypt(private_key, cipher_text)` → plaintext

Використовується бібліотека `cryptography` (OAEP + SHA-256).

При старті сервер автоматично генерує 10 пар RSA-ключів (як на sequence-діаграмі).

---

## Завдання 2 — AES

### AesService (shared)

- `generate_secret_key()` → `AesKey(key, iv)` (AES-256 + 16-byte IV)
- `encrypt(aes_key, plain_text)` → Base64 ciphertext
- `decrypt(aes_key, cipher_text)` → plaintext

Режим: **AES-256-CBC** з PKCS7 padding.

---

## Завдання 3 — Безпечна комунікація

### Додаткові endpoints

| Method | Endpoint | Headers | Опис |
|--------|----------|---------|------|
| `POST` | `/api/secure/session` | `x-rsa-id` | Клієнт надсилає RSA-зашифрований JSON з `session_id`, `aes_key`, `aes_iv`. Сервер розшифровує private key і зберігає сесію. |
| `POST` | `/api/secure/message` | `x-session-id` | Клієнт надсилає AES-зашифроване повідомлення. Сервер розшифровує, додає `received_at` (UTC ISO), знову шифрує і повертає. |
| `GET`  | `/health` | — | Health-check |

### Алгоритм (відповідає sequence-діаграмі)

1. Користувач вводить повідомлення.
2. Клієнт генерує нову пару RSA-ключів на сервері та отримує public key + `x-rsa-id`.
3. Клієнт генерує AES key + IV + `session_id`.
4. Клієнт шифрує JSON `{session_id, aes_key, aes_iv}` публічним RSA-ключем і надсилає на `/api/secure/session` з заголовком `x-rsa-id`.
5. Сервер розшифровує, зберігає AES-ключ за `session_id`, повертає підтвердження.
6. Клієнт шифрує повідомлення AES і надсилає на `/api/secure/message` з `x-session-id`.
7. Сервер розшифровує, додає timestamp, шифрує відповідь.
8. Клієнт розшифровує відповідь і виводить на екран (разом із Session ID).
9. Можна вводити нові повідомлення в тій самій сесії. Команда `exit` — вихід.

---

## Запуск локально (без Docker)

```bash
# 1. Встановити залежності
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt

# 2. Запустити сервер (з кореня проєкту)
set PYTHONPATH=.
uvicorn server.app.main:app --reload --host 0.0.0.0 --port 8000

# 3. В іншому терміналі — клієнт
set PYTHONPATH=.
set SERVER_URL=http://localhost:8000
python -m client.app.main
```

Swagger UI: **http://localhost:8000/docs**

---

## Запуск через Docker

```bash
# Зібрати і запустити сервер
docker compose up --build -d

# Перевірити, що сервер живий
curl http://localhost:8000/health

# Запустити інтерактивний клієнт
docker compose run --rm client
```

Або одним рядком (сервер у фоні + клієнт):

```bash
docker compose up --build -d server
docker compose run --rm client
```

Клієнт підключається до сервера за ім’ям сервісу `http://server:8000` (не localhost).

---

## Тести

```bash
# З кореня проєкту
pip install -r requirements.txt
pytest -v
```

Тести покривають:

- генерацію RSA/AES ключів
- encrypt/decrypt round-trip
- API: генерація ключів, отримання public key, 404
- повний secure flow (session + message)

---

## GitHub Actions (CI)

Файл `.github/workflows/ci.yml` автоматично:

1. Встановлює Python 3.12
2. Ставить залежності
3. Запускає `pytest`
4. Збирає Docker-образи server і client

Після push у `main`/`master` workflow запускається сам.

---

## Приклад роботи клієнта

```
============================================================
  Lab 6 – Безпечна комунікація (RSA + AES)
============================================================
Сервер: http://localhost:8000
Введіть повідомлення для відправки. Команда 'exit' — вихід.

Отримую RSA public key з сервера...
[OK] Отримано RSA public key (id=11)
Створюю AES session...
[OK] Сесію встановлено. Session ID: 3f8a2b1c-...

Ваше повідомлення > Hello from secure client!
--------------------------------------------------
Session ID : 3f8a2b1c-...
Ваше повідомлення : Hello from secure client!
Відповідь сервера  : Hello from secure client! [received_at=2026-11-14T21:45:12.123456+00:00]
--------------------------------------------------

Ваше повідомлення > exit
Вихід.
```

---

## Технології

- **Python 3.12**
- **FastAPI** + Uvicorn (OpenAPI/Swagger автоматично)
- **cryptography** (RSA OAEP, AES-256-CBC)
- **Pydantic** v2
- **pytest**
- **Docker** + Docker Compose
- **GitHub Actions**

---

## Автор

Студент кафедри інтелектуальних програмних систем і технологій  
Харківський національний університет імені В.Н. Каразіна
