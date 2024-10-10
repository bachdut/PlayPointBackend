"""Change profile_picture to Text for base64 storage

Revision ID: 423b7da5c928
Revises: 
Create Date: 2024-10-10 20:31:21.834959

"""
from alembic import op
import sqlalchemy as sa
from alembic import context

# revision identifiers, used by Alembic.
revision = '423b7da5c928'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Use batch_alter_table to handle SQLite constraints
    with op.batch_alter_table('user', schema=None) as batch_op:
        # First, check if the column exists before trying to alter it
        conn = op.get_bind()
        inspector = sa.inspect(conn)
        columns = inspector.get_columns('user')
        column_names = [c['name'] for c in columns]
        
        if 'profile_picture' in column_names:
            batch_op.alter_column('profile_picture',
                           existing_type=sa.LargeBinary(),
                           type_=sa.Text(),
                           existing_nullable=True)
        else:
            batch_op.add_column(sa.Column('profile_picture', sa.Text(), nullable=True))

def downgrade():
    # Use batch_alter_table to handle SQLite constraints
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('profile_picture',
                       existing_type=sa.Text(),
                       type_=sa.LargeBinary(),
                       existing_nullable=True)