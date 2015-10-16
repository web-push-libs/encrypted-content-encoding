from setuptools import setup

setup(
    name='http_ece',
    version='0.2.0',
    author='Martin Thomson',
    author_email='martin.thomson@gmail.com',
    scripts=[],
    packages=['http_ece'],
    description='Encrypted Content Encoding for HTTP',
    long_description='Encipher HTTP Messages',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='crypto http',
    install_requires=[
        'pyelliptic', 'cryptography'
    ],
    url='https://github.com/martinthomson/encrypted-content-encoding',
    license='MIT'
)
