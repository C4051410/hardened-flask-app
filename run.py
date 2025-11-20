# run.py
import os
from app import create_app

# Part I: Determine configuration environment
config_name = os.environ.get('FLASK_ENV', 'development')
app = create_app(config_name)

if __name__ == '__main__':
    # Running with debug=False in production is handled by the config class (Part I)
    app.run()