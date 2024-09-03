from PyInstaller.utils.hooks import collect_data_files

# Collect only SSM data files from botocore
datas = collect_data_files('botocore', subdir='data/ssm')
