import get
import put

data_file = "test_data.csv"
bucket = "reinquire-example-prod"
key = "encryption_test.csv"
kms_arn = "arn:aws:kms:us-east-1:044682350103:key/b93a966b-5bf3-495b-948b-f4b6d44b2ea4"

# put.put_encrypted_object(data_file, bucket, key, kms_arn)

decrypted_file = "decryption_test.csv"

get.get_decrypted_file(bucket, key, decrypted_file)

