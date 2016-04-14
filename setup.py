from setuptools import setup

setup(name='miracl_api_tornado',
      version='0.1',
      description='SDK for using Miracl authentication',
      url='https://github.com/miracl/maas-sdk-tornado',
      author='Elviss Kustans',
      author_email='n3o59hf@gmail.com',
      license='TBD',
      packages=['miracl_api_tornado'],
      install_requires=[
          'tornado',
          'future'  # https://github.com/rohe/pyoidc/issues/188
      ],
      zip_safe=False)
