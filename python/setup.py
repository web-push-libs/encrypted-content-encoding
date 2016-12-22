#!/usr/bin/python
import io
import os

from setuptools import setup


def read_from(req_file):
    reply = []
    with io.open(os.path.join(here, req_file), encoding='utf8') as data:
        for l in data:
            l = l.strip()
            if not l:
                break
            if l[:2] == '-r':
                reply.extend(read_from(l.split(' ')[1]))
                continue
            if l[0] != '#' or l[:2] != '//':
                reply.append(l)
    return reply


here = os.path.abspath(os.path.dirname(__file__))
with io.open(os.path.join(here, 'README.rst'), encoding='utf8') as f:
        README = f.read()


setup(
    name='http_ece',
    version='0.6.0',
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
    install_requires=read_from('requirements.txt'),
    tests_require=read_from('test-requirements.txt'),
    test_suite="nose.collector",
    url='https://github.com/martinthomson/encrypted-content-encoding',
    license='MIT'
)
