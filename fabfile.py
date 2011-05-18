from __future__ import with_statement
from fabric.api import *
from fabric.contrib.console import confirm
from fabric.contrib.files import upload_template, exists
import getpass

env.key_filename = "/home/%s/.ssh/id_rsa" % getpass.getuser()

APP_NAME='wire'
DEFAULT_USER= getpass.getuser()
DEFAULT_DIRECTORY='/srv/%s' % APP_NAME

def install(user=DEFAULT_USER, socket=False, directory=DEFAULT_DIRECTORY):
    production(user=user, socket=socket, directory=directory)
    deploy_pip()
    conf_supervisor()
    start()

def production(user=DEFAULT_USER, socket=False, directory=DEFAULT_DIRECTORY):
    env.deploy_user = user
    default_envs(directory)
    if not socket:
        socket = '/tmp/gunicorn_%s.sock' % env.name
    env.socket = socket 

def default_envs(directory):
    env.name = APP_NAME
    env.directory = directory
    env.virt_path = '/home/%s/.virt_env/%s' % (env.deploy_user,  env.name)
    env.activate = 'source %s/bin/activate' % env.virt_path
    
def debug(directory=DEFAULT_DIRECTORY, user=DEFAULT_USER):
    env.deploy_user = user
    default_envs(directory)
    env.name = 'wire'
    virtualenv('python debug.py')
    
def user_add():
    with settings(warn_only=True):
        sudo('useradd -m %s' % env.deploy_user)

def make_dir():
    with settings(warn_only=True):
        sudo('mkdir -p %s && chown %s %s' % (env.directory, env.deploy_user, env.directory))

def conf_supervisor(gunicorn_config='/etc/gunicorn.conf.py'):
    with settings(warn_only=True):
        with settings(hide('warnings', 'running', 'stdout', 'stderr')):
            sudo('mkdir -p /etc/supervisor.d')
        skel_data = {
            'name': env.name,
            'user': env.deploy_user,
            'app': env.name+':app',
            'gunicorn_config': gunicorn_config,
            'socket': env.socket,
            'directory': env.directory
        }
        path = '/etc/supervisor.d/%s.conf' % env.name
        upload_template('skeletons/supervisor.skel', path, skel_data, use_sudo=True)
        print "Written supervisor config for %s." % env.name

def start():
    with settings(hide('warnings'), warn_only=True):
        sudo('supervisorctl reload')
        sudo('supervisorctl stop %s' % env.name)
        sudo('rm %s -f' % env.socket)
        sudo('supervisorctl start %s' % env.name)

def virtualenv(command):
    with cd(env.directory):
        sudo(env.activate + ' && ' + command, user=env.deploy_user)

def git_pull():
    'Updates the repository.'
    url = "git://github.com/radiosilence/%s.git" % env.name
    if not exists(env.directory):
        sudo('mkdir -p %s && chown %s %s' % (env.directory, env.deploy_user, env.directory))
    with settings(warn_only=True):
        with cd(env.directory):
            clone = sudo('git clone %s %s' % (url, env.directory),
                user=env.deploy_user)
            if clone.failed:
                sudo('chown %s . -R' % (env.deploy_user))
                sudo('git remote rm origin; git remote add origin %s' % url, 
                    user=env.deploy_user)
                pull = sudo('git pull origin master', user=env.deploy_user)
     
def make_virt():
    sudo('mkdir -p %s; mkdir -p /home/%s/.tmp' %
        (env.virt_path, env.deploy_user))
    sudo('export TMPDIR=/home/%s/.tmp && virtualenv %s --no-site-packages --clear'
        % (env.deploy_user, env.virt_path), user=env.deploy_user)

def pip_install_req():
    virtualenv('pip install -r %s/REQUIREMENTS' % env.directory)

def deploy_pip():
    local('git push origin master')
    git_pull()
    make_virt()
    pip_install_req()
