FROM python:3.7-slim
RUN pip install --trusted-host pypi.python.org pyraider
CMD ["python"]