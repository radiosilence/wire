from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm


def production():
    env.hosts = ['james@localhost']
    env.deploy_user = "james"
    env.parent_directory = '/var/www/apps'
    env.directory = '%s/wire' % env.parent_directory
    env.virt_path = '~/.virt_env/wire'
    env.activate = 'source %s/bin/activate' % env.virt_path

def user_add():
    with settings(warn_only=True):
        sudo('useradd -m %s' % env.deploy_user)

def make_dir():
    with settings(warn_only=True):
        sudo('mkdir -p %s && chown %s %s' % (env.directory, env.deploy_user, env.directory))

def virtualenv(command):
    with cd(env.directory):
        sudo(env.activate + '&&' + command, user=env.deploy_user)

def git_pull():
    'Updates the repository.'
    with cd(env.parent_directory):
        sudo('git clone git://github.com/radiosilence/wire.git wire || (cd wire && git pull origin master)', user=env.deploy_user)

def make_virt():
    sudo('virtualenv %s --no-site-packages' % env.virt_path, user=env.deploy_user)

def pip_install_req():
    virtualenv('pip install -U -r -q %s/REQUIREMENTS' % env.directory)

def deploy_pip():
    local('git push origin master')
    git_pull()
    make_virt()
    pip_install_req()
    
