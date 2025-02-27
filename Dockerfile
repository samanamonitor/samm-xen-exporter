FROM python:3.12

COPY . /app

WORKDIR /app

RUN <<EOF
python3 -m pip install -r /app/requirements.txt
EOF

ENTRYPOINT [ "/bin/bash" ]