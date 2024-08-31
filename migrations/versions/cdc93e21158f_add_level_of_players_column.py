from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'cdc93e21158f'
down_revision = '4e548dc223ba'
branch_labels = None
depends_on = None

def upgrade():
    op.drop_table('_alembic_tmp_court')
    with op.batch_alter_table('court', schema=None) as batch_op:
        batch_op.add_column(sa.Column('level_of_players', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('category', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('players_joined', sa.Integer(), nullable=False))
        batch_op.drop_column('time_slots')

    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.add_column(sa.Column('game_id', sa.Integer(), nullable=False))
        batch_op.alter_column('user_name', existing_type=sa.VARCHAR(length=120), type_=sa.String(length=80), existing_nullable=False)
        batch_op.alter_column('reserved_on', existing_type=sa.DATETIME(), nullable=True)
        # batch_op.drop_constraint('fk_court_id', type_='foreignkey')  # Commenting this out to avoid the error
        batch_op.create_foreign_key('fk_game_id', 'game', ['game_id'], ['id'])
        batch_op.drop_column('court_name')
        batch_op.drop_column('reserved_time_slot')
        batch_op.drop_column('court_id')

def downgrade():
    with op.batch_alter_table('reservation', schema=None) as batch_op:
        batch_op.add_column(sa.Column('court_id', sa.INTEGER(), nullable=False))
        batch_op.add_column(sa.Column('reserved_time_slot', sa.VARCHAR(length=50), nullable=False))
        batch_op.add_column(sa.Column('court_name', sa.VARCHAR(length=120), nullable=False))
        batch_op.drop_constraint('fk_game_id', type_='foreignkey')
        batch_op.create_foreign_key('fk_court_id', 'court', ['court_id'], ['id'])  # Correct the name if necessary
        batch_op.alter_column('reserved_on', existing_type=sa.DATETIME(), nullable=False)
        batch_op.alter_column('user_name', existing_type=sa.String(length=80), type_=sa.VARCHAR(length=120), existing_nullable=False)
        batch_op.drop_column('game_id')

    with op.batch_alter_table('court', schema=None) as batch_op:
        batch_op.add_column(sa.Column('time_slots', sa.VARCHAR(length=500), nullable=True))
        batch_op.drop_column('players_joined')
        batch_op.drop_column('category')
        batch_op.drop_column('level_of_players')