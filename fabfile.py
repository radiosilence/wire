from __future__ import with_statement
from fabric.api import *
from fabric.contrib.files import upload_template, exists
import getpass

env.key_filename = "/home/%s/.ssh/id_rsa" % getpass.getuser()

APP_NAME = 'wire'
DEFAULT_USER = getpass.getuser()
DEFAULT_DIRECTORY = '/srv/%s'

env.summary = ['SUMMARY FOR [%s] DEPLOYMENT' % APP_NAME]


def deploy(**kwargs):
    production(**kwargs)
    deploy_pip()
    conf_supervisor()
    start()
    show_config()

    print "\n\n"
    print " ******************************************************************\
*******"
    print " * " + env.summary.pop(0)
    print " ******************************************************************\
*******"
    print " *\n *  - " + "\n *  - ".join(env.summary)
    print " *\n **************************************************************\
***********"


def production(socket=False, **kwargs):
    default_envs(**kwargs)
    if not socket:
        socket = '/tmp/gunicorn_%s.sock' % env.name
    env.socket = socket
    env.summary.append("Configured for production.")


def default_envs(directory=False, user=DEFAULT_USER, name=APP_NAME):
    env.deploy_user = user
    env.name = name
    if not directory:
        env.directory = DEFAULT_DIRECTORY % env.name
    else:
        env.directory = directory
    env.virt_path = '/home/%s/.virt_env/%s' % (env.deploy_user,  env.name)
    env.activate = 'source %s/bin/activate' % env.virt_path


def user_add():
    with settings(warn_only=True):
        sudo('useradd -m %s' % env.deploy_user)
    env.summary.append('Added user "%s".' % env.deploy_user)


def make_dir():
    with settings(warn_only=True):
        sudo('mkdir -p %s && chown %s %s' %
            (env.directory, env.deploy_user, env.directory))


def conf_supervisor(gunicorn_config='/etc/gunicorn.conf.py'):
    with settings(warn_only=True):
        with settings(hide('warnings', 'running', 'stdout', 'stderr')):
            sudo('mkdir -p /etc/supervisor.d')
        skel_data = {
            'name': env.name,
            'user': env.deploy_user,
            'app': APP_NAME + ':app',
            'gunicorn_config': gunicorn_config,
            'socket': env.socket,
            'directory': env.directory
        }
        path = '/etc/supervisor.d/%s.conf' % env.name
        upload_template('skeletons/supervisor.skel',
            path, skel_data, use_sudo=True)

    env.summary.append('Written supervisor config to "%s".' % path)


def start():
    with settings(hide('warnings'), warn_only=True):
        sudo('supervisorctl reload')
        sudo('supervisorctl stop %s' % env.name)
        sudo('rm %s -f' % env.socket)
        sudo('supervisorctl start %s' % env.name)
    env.summary.append('Started process with supervisor.')


def virtualenv(command):
    with cd(env.directory):
        sudo(env.activate + ' && ' + command, user=env.deploy_user)


def git_pull():
    'Updates the repository.'
    url = "git://github.com/radiosilence/%s.git" % APP_NAME
    if not exists(env.directory):
        sudo('mkdir -p %s && chown %s %s' %
            (env.directory, env.deploy_user, env.directory))
    with settings(warn_only=True):
        with cd(env.directory):
            clone = sudo('git clone %s %s' % (url, env.directory),
                user=env.deploy_user)
            if clone.failed:
                sudo('chown %s . -R' % (env.deploy_user))
                sudo('git remote rm origin; git remote add origin %s' % url,
                    user=env.deploy_user)
                sudo('git pull origin master', user=env.deploy_user)


def make_virt():
    sudo('mkdir -p %s; mkdir -p /home/%s/.tmp' %
        (env.virt_path, env.deploy_user))
    sudo('export TMPDIR=/home/%s/.tmp && virtualenv %s --no-site-packages'
        % (env.deploy_user, env.virt_path))
    sudo('chown %s %s -R' % (env.deploy_user, env.virt_path))
    env.summary.append('Created virtualenv in "%s".' % env.virt_path)


def pip_install_req():
    virtualenv('pip install -r %s/REQUIREMENTS' % env.directory)
    env.summary.append('Pip installed requirements from "%s/REQUIREMENTS".' %
        env.directory)


def show_config():
    if not exists("%s/config.py" % env.directory):
        sudo('cp %s/config.py.sample %s/config.py' %
            (env.directory, env.directory), user=env.deploy_user)
        env.summary.append('Created new config file "%s/config.py". Please \
edit and then run "fab start"'
            % env.directory)


def deploy_pip():
    git_pull()
    make_virt()
    pip_install_req()
