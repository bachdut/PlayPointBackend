"""Add additional fields to Court model

Revision ID: a0d429da691a
Revises: f520c58933d0
Create Date: 2024-07-07 00:19:12.760774

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a0d429da691a'
down_revision = 'f520c58933d0'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('court', schema=None) as batch_op:
        batch_op.add_column(sa.Column('price', sa.Float(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('available_date', sa.Date(), nullable=False, server_default='1970-01-01'))
        batch_op.add_column(sa.Column('available_time', sa.String(length=50), nullable=False, server_default='00:00 - 00:00'))
        batch_op.add_column(sa.Column('image', sa.String(length=200), nullable=True))

    # Remove the server defaults after setting the default values
    with op.batch_alter_table('court', schema=None) as batch_op:
        batch_op.alter_column('price', server_default=None)
        batch_op.alter_column('available_date', server_default=None)
        batch_op.alter_column('available_time', server_default=None)

def downgrade():
    with op.batch_alter_table('court', schema=None) as batch_op:
        batch_op.drop_column('price')
        batch_op.drop_column('available_date')
        batch_op.drop_column('available_time')
        batch_op.drop_column('image')