FROM public.ecr.aws/lambda/python:3.13

COPY jobs ${LAMBDA_TASK_ROOT}/jobs
COPY maskinporten_api ${LAMBDA_TASK_ROOT}/maskinporten_api
COPY models ${LAMBDA_TASK_ROOT}/models
COPY resources ${LAMBDA_TASK_ROOT}/resources
COPY app.py ./
COPY handler.py ./
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD ["set-me-in-serverless.yaml"]
