"""Change profile_picture to Text for base64 storage

Revision ID: 423b7da5c928
Revises: <previous_revision_id>
Create Date: <timestamp>

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '423b7da5c928'
down_revision = '<previous_revision_id>'  # Make sure this matches your actual previous revision
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
        
        # Remove this line as the column doesn't exist
        # batch_op.drop_column('temp_profile_picture')

def downgrade():
    # Use batch_alter_table to handle SQLite constraints
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.alter_column('profile_picture',
                       existing_type=sa.Text(),
                       type_=sa.LargeBinary(),
                       existing_nullable=True)