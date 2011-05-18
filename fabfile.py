from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm

env.hosts = ['james@localhost']

def production():
    env.hosts = ['servername']
    env.directory = '/var/www/apps/wire'
    env.deploy_user = "deploy"
    env.activate = 'source /home/%s/.virtualenvs/project/bin/activate' % env.deploy_user


def virtualenv(command):
    with cd(env.directory):
        sudo(env.activate + '&&' + command, user=env.deploy_user)

def git_pull()
    'Updates the repository.'
    with cd(env.directory):
        sudo('git pull', user=env.deploy_user)

def pip_install_req():
    virtualenv('pip install -U -r %s/REQUIREMENTS' % env.directory))

def deploy_pip():
    local('git push')
    git_pull()
    pip_install_req()
    
