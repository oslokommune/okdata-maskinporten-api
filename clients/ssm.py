import boto3


class SSMClient:
    def __init__(self):
        self.client = boto3.client("ssm", region_name=os.environ["AWS_REGION"])

    def get_ssm_parameters(self, parameter_names, with_decryption=False):
        parameters = self.client.get_parameters(
            Names=parameter_names, WithDecryption=with_decryption
        )["Parameters"]
        parameters_dict = {}
        for parameter in parameters:
            parameters_dict[parameter["Name"]] = parameter["Value"]

        return parameters_dict
