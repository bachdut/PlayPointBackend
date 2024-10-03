"""Add share_link to Game model

Revision ID: 2904cc617b39
Revises: 97947842f57c
Create Date: 2024-10-02 22:47:22.266499

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2904cc617b39'
down_revision = '97947842f57c'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('game', schema=None) as batch_op:
        batch_op.add_column(sa.Column('share_link', sa.String(length=255), nullable=True))
        batch_op.create_unique_constraint('uq_game_share_link', ['share_link'])

def downgrade():
    with op.batch_alter_table('game', schema=None) as batch_op:
        batch_op.drop_constraint('uq_game_share_link', type_='unique')
        batch_op.drop_column('share_link')