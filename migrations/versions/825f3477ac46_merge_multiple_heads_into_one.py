"""Merge multiple heads into one

Revision ID: 825f3477ac46
Revises: 136b65e0b86e, 423b7da5c928, da3963bdf7ca
Create Date: 2024-10-11 02:06:27.507300

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '825f3477ac46'
down_revision = ('136b65e0b86e', '423b7da5c928', 'da3963bdf7ca')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
