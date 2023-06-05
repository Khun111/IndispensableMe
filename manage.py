#!/usr/bin/env python3
from flask_migrate import MigrateCommand
from .app import Manager

manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()
