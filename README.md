# gdc HW
Runs with Python Unittest framework

- test_good_credentials
- test_logout_authorized
- test_negative_logout_exists_user_by_another
- test_negative_logout_exists_user_while_logout
- test_negative_logout_not_exists_user
- test_negative_wrong_credentials

Fill up config_file with proper (of two users) and wrong credentials and run tests from commandline:
`python -m unittest discover -v`

