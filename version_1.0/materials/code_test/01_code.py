import yaml

def load_yaml(yaml_payload):
	prod_and_qt = yaml.load(yaml_payload)
	return prod_and_qt

yaml_payload = "" 
prod_and_qt = load_yaml(yaml_payload)
print(prod_and_qt)
