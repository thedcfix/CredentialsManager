FROM python:3.6
COPY . /app
WORKDIR /app

RUN pip install flask
RUN pip install pymongo

CMD ["python", "web.py"]