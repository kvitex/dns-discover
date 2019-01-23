FROM python:3.7.2-alpine3.8

WORKDIR /opt/app

COPY requirements.txt ./
RUN pip install --disable-pip-version-check --no-cache-dir -r requirements.txt

COPY . .

CMD [ "sh", "start_app.sh", "0.0.0.0", "9053" ]
