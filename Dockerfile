FROM python:3.6
COPY . /app
WORKDIR /app

RUN pip install flask
RUN pip install pymongo
RUN pip install cryptography

CMD ["python", "web.py"]