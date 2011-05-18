from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm


def production():
    env.hosts = ['james@localhost']
    env.directory = '/var/www/apps/wire'
    env.deploy_user = "deploy"
    env.path = env.directory+'/virt_env/'
    env.activate = 'source %s/bin/activate' % env.path

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
    with cd(env.directory):
        sudo('git clone git://github.com/radiosilence/wire.git .', user=env.deploy_user)

def make_virt():
    with cd(env.directory):
        sudo('virtualenv . --no-site-packages', user=env.deploy_user)

def pip_install_req():
    virtualenv('pip install -U -r %s/REQUIREMENTS' % env.directory)

def deploy_pip():
    local('git push origin master')
    #user_add()
    #make_dir()
    git_pull()
    make_virt()
    pip_install_req()
    
