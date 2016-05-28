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
      tests_require=[
            'mock==2.0.0',
            'tornado-stub-client==0.2'
      ],
      test_suite='tests.test_suite',
      zip_safe=False)
