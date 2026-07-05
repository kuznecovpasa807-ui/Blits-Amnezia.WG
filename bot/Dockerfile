FROM python:3.12-slim

WORKDIR /bot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY telegram_bot.py .

ENV PYTHONUNBUFFERED=1

CMD ["python", "telegram_bot.py"]
