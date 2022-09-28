FROM python:3.10

WORKDIR /API/

COPY ./requirements.txt /API/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /API/requirements.txt

COPY . /API/

CMD ["uvicorn", "oneapi:app", "--host", "0.0.0.0", "--port", "8000"]