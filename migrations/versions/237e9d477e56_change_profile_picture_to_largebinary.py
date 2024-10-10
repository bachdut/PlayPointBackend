"""Change profile_picture to LargeBinary

Revision ID: 237e9d477e56
Revises: 3a550b6fa03f
Create Date: 2024-10-10 02:57:47.653574

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '237e9d477e56'
down_revision = '3a550b6fa03f'
branch_labels = None
depends_on = None



def upgrade():
    # Create a temporary column
    op.add_column('user', sa.Column('temp_profile_picture', sa.LargeBinary()))

    # Copy data from the old column to the new column, converting to binary
    op.execute("UPDATE \"user\" SET temp_profile_picture = decode(profile_picture, 'base64') WHERE profile_picture IS NOT NULL")

    # Drop the old column
    op.drop_column('user', 'profile_picture')

    # Rename the new column to the original name
    op.alter_column('user', 'temp_profile_picture', new_column_name='profile_picture')

def downgrade():
    # If you need to reverse this migration, you'd do the opposite
    op.add_column('user', sa.Column('temp_profile_picture', sa.String(256)))
    op.execute("UPDATE \"user\" SET temp_profile_picture = encode(profile_picture, 'base64') WHERE profile_picture IS NOT NULL")
    op.drop_column('user', 'profile_picture')
    op.alter_column('user', 'temp_profile_picture', new_column_name='profile_picture')