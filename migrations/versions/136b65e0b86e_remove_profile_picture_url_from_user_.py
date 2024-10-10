"""Remove profile_picture_url from User model

Revision ID: 136b65e0b86e
Revises: 237e9d477e56
Create Date: 2024-10-10 20:31:21.834959

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine.reflection import Inspector

# revision identifiers, used by Alembic.
revision = '136b65e0b86e'
down_revision = '237e9d477e56'
branch_labels = None
depends_on = None


def upgrade():
    # Check if the column exists before trying to drop it
    conn = op.get_bind()
    inspector = Inspector.from_engine(conn)
    columns = inspector.get_columns('user')
    if any(column['name'] == 'profile_picture_url' for column in columns):
        with op.batch_alter_table('user', schema=None) as batch_op:
            batch_op.drop_column('profile_picture_url')


def downgrade():
    # We won't add the column back in the downgrade since it might not have existed
    pass