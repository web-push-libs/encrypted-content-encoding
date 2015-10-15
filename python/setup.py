from setuptools import setup

setup(
    name='http_ece',
    version='1.0.0',
    author='Martin Thomson',
    author_email='martin.thomson@gmail.com',
    scripts=[],
    packages=['http_ece'],
    description='Encrypted Content Encoding for HTTP',
    long_description='Enciper HTTP Messages',
    install_requires=[
        'pyelliptic', 'cryptography'
    ],
    url='https://github.com/martinthomson/encrypted-content-encoding',
    license='MIT'
)
